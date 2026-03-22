# IPC Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The IPC namespace isolates **System V IPC objects** and **POSIX message queues**. That includes shared memory segments, semaphores, and message queues that would otherwise be visible across unrelated processes on the host. In practical terms, this prevents a container from casually attaching to IPC objects belonging to other workloads or the host.

Compared with mount, PID, or user namespaces, the IPC namespace is often discussed less often, but that should not be confused with irrelevance. Shared memory and related IPC mechanisms can contain highly useful state. If the host IPC namespace is exposed, the workload may gain visibility into inter-process coordination objects or data that was never intended to cross the container boundary.

## Operation

When the runtime creates a fresh IPC namespace, the process gets its own isolated set of IPC identifiers. This means commands such as `ipcs` show only the objects available in that namespace. If the container instead joins the host IPC namespace, those objects become part of a shared global view.

This matters especially in environments where applications or services use shared memory heavily. Even when the container cannot directly break out through IPC alone, the namespace may leak information or enable cross-process interference that materially helps a later attack.

## Lab

You can create a private IPC namespace with:

```bash
sudo unshare --ipc --fork bash
ipcs
```

And compare runtime behavior with:

```bash
docker run --rm debian:stable-slim ipcs
docker run --rm --ipc=host debian:stable-slim ipcs
```

## Runtime Usage

Docker and Podman isolate IPC by default. Kubernetes typically gives the Pod its own IPC namespace, shared by containers in the same Pod but not by default with the host. Host IPC sharing is possible, but it should be treated as a meaningful reduction in isolation rather than a minor runtime option.

## Misconfigurations

The obvious mistake is `--ipc=host` or `hostIPC: true`. This may be done for compatibility with legacy software or for convenience, but it changes the trust model substantially. Another recurring issue is simply overlooking IPC because it feels less dramatic than host PID or host networking. In reality, if the workload handles browsers, databases, scientific workloads, or other software that makes heavy use of shared memory, the IPC surface can be very relevant.

## Abuse

When host IPC is shared, an attacker may inspect or interfere with shared memory objects, gain new insight into host or neighboring workload behavior, or combine the information learned there with process visibility and ptrace-style capabilities. IPC sharing is often a supporting weakness rather than the full breakout path, but supporting weaknesses matter because they shorten and stabilize real attack chains.

The first useful step is to enumerate what IPC objects are visible at all:

```bash
readlink /proc/self/ns/ipc
ipcs -a
ls -la /dev/shm 2>/dev/null | head -n 50
```

If the host IPC namespace is shared, large shared-memory segments or interesting object owners can reveal application behavior immediately:

```bash
ipcs -m -p
ipcs -q -p
```

In some environments, `/dev/shm` contents themselves leak filenames, artifacts, or tokens worth checking:

```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -ls | head -n 50
strings /dev/shm/* 2>/dev/null | head -n 50
```

IPC sharing rarely gives instant host root by itself, but it can expose data and coordination channels that make later process attacks far easier.

### Full Example: `/dev/shm` Secret Recovery

The most realistic full abuse case is data theft rather than direct escape. If host IPC or a broad shared-memory layout is exposed, sensitive artifacts can sometimes be recovered directly:

```bash
find /dev/shm -maxdepth 2 -type f 2>/dev/null -print
strings /dev/shm/* 2>/dev/null | grep -Ei 'token|secret|password|jwt|key'
```

Impact:

- extraction of secrets or session material left in shared memory
- insight into the applications currently active on the host
- better targeting for later PID-namespace or ptrace-based attacks

IPC sharing is therefore better understood as an **attack amplifier** than as a standalone host-escape primitive.

## Checks

These commands are meant to answer whether the workload has a private IPC view, whether meaningful shared-memory or message objects are visible, and whether `/dev/shm` itself exposes useful artifacts.

```bash
readlink /proc/self/ns/ipc   # Namespace identifier for IPC
ipcs -a                      # Visible SysV IPC objects
mount | grep shm             # Shared-memory mounts, especially /dev/shm
```

What is interesting here:

- If `ipcs -a` reveals objects owned by unexpected users or services, the namespace may not be as isolated as expected.
- Large or unusual shared memory segments are often worth following up on.
- A broad `/dev/shm` mount is not automatically a bug, but in some environments it leaks filenames, artifacts, and transient secrets.

IPC rarely receives as much attention as the bigger namespace types, but in environments that use it heavily, sharing it with the host is very much a security decision.
{{#include ../../../../../banners/hacktricks-training.md}}
