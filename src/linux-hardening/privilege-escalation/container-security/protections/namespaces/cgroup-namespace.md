# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The cgroup namespace does not replace cgroups and does not itself enforce resource limits. Instead, it changes **how the cgroup hierarchy appears** to the process. In other words, it virtualizes the visible cgroup path information so that the workload sees a container-scoped view rather than the full host hierarchy.

This is mainly a visibility and information-reduction feature. It helps make the environment look self-contained and reveals less about the host's cgroup layout. That may sound modest, but it still matters because unnecessary visibility into host structure can aid reconnaissance and simplify environment-dependent exploit chains.

## Operation

Without a private cgroup namespace, a process may see host-relative cgroup paths that expose more of the machine's hierarchy than is useful. With a private cgroup namespace, `/proc/self/cgroup` and related observations become more localized to the container's own view. This is particularly helpful in modern runtime stacks that want the workload to see a cleaner, less host-revealing environment.

## Lab

You can inspect a cgroup namespace with:

```bash
sudo unshare --cgroup --fork bash
cat /proc/self/cgroup
ls -l /proc/self/ns/cgroup
```

And compare runtime behavior with:

```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```

The change is mostly about what the process can see, not about whether cgroup enforcement exists.

## Security Impact

The cgroup namespace is best understood as a **visibility-hardening layer**. By itself it will not stop a breakout if the container has writable cgroup mounts, broad capabilities, or a dangerous cgroup v1 environment. However, if the host cgroup namespace is shared, the process learns more about how the system is organized and may find it easier to line up host-relative cgroup paths with other observations.

So while this namespace is not usually the star of container breakout writeups, it still contributes to the broader goal of minimizing host information leakage.

## Abuse

The immediate abuse value is mostly reconnaissance. If the host cgroup namespace is shared, compare the visible paths and look for host-revealing hierarchy details:

```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
```

If writable cgroup paths are also exposed, combine that visibility with a search for dangerous legacy interfaces:

```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```

The namespace itself rarely gives instant escape, but it often makes the environment easier to map before testing cgroup-based abuse primitives.

### Full Example: Shared cgroup Namespace + Writable cgroup v1

The cgroup namespace alone is usually not enough for escape. The practical escalation happens when host-revealing cgroup paths are combined with writable cgroup v1 interfaces:

```bash
cat /proc/self/cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null | head
```

If those files are reachable and writable, pivot immediately into the full `release_agent` exploitation flow from [cgroups.md](../cgroups.md). The impact is host code execution from inside the container.

Without writable cgroup interfaces, the impact is usually limited to reconnaissance.

## Checks

The point of these commands is to see whether the process has a private cgroup namespace view or is learning more about the host hierarchy than it really needs.

```bash
readlink /proc/self/ns/cgroup   # Namespace identifier for cgroup view
cat /proc/self/cgroup           # Visible cgroup paths from inside the workload
mount | grep cgroup             # Mounted cgroup filesystems and their type
```

What is interesting here:

- If the namespace identifier matches a host process you care about, the cgroup namespace may be shared.
- Host-revealing paths in `/proc/self/cgroup` are useful reconnaissance even when they are not directly exploitable.
- If cgroup mounts are also writable, the visibility question becomes much more important.

The cgroup namespace should be treated as a visibility-hardening layer rather than as a primary escape-prevention mechanism. Exposing host cgroup structure unnecessarily adds reconnaissance value for the attacker.
