# cgroup Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The cgroup namespace does not replace cgroups and does not itself enforce resource limits. Instead, it changes **how the cgroup hierarchy appears** to the process. In other words, it virtualizes the visible cgroup path information so that the workload sees a container-scoped view rather than the full host hierarchy.

This is mainly a visibility and information-reduction feature. It helps make the environment look self-contained and reveals less about the host's cgroup layout. That may sound modest, but it still matters because unnecessary visibility into host structure can aid reconnaissance and simplify environment-dependent exploit chains.

## Operation

Without a private cgroup namespace, a process may see host-relative cgroup paths that expose more of the machine's hierarchy than is useful. With a private cgroup namespace, `/proc/self/cgroup` and related observations become more localized to the container's own view. This is particularly helpful in modern runtime stacks that want the workload to see a cleaner, less host-revealing environment.

The virtualization also affects `/proc/<pid>/mountinfo`, not only `/proc/<pid>/cgroup`. When you read another process from a different cgroup-namespace perspective, paths outside your namespace root are shown with leading `../` components, which is a handy clue that you are looking above your delegated subtree. A useful nuance for labs and post-exploitation is that a freshly created cgroup namespace often needs a **cgroupfs remount from inside that namespace** before `mountinfo` reflects the new root cleanly. Otherwise you may still see a mount root such as `/..`, which means the inherited mount is still exposing an ancestor-rooted view even though the namespace itself already changed.

## Lab

You can inspect a cgroup namespace with:

```bash
sudo unshare --cgroup --mount --fork bash
cat /proc/self/cgroup
cat /proc/self/mountinfo | grep cgroup
ls -l /proc/self/ns/cgroup
```

If you want `mountinfo` to show the new cgroup-namespace root more clearly, remount the cgroup filesystem from inside the new namespace and compare again:

```bash
mount --make-rslave /
umount /sys/fs/cgroup 2>/dev/null
mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```

And compare runtime behavior with:

```bash
docker run --rm debian:stable-slim cat /proc/self/cgroup
docker run --rm --cgroupns=host debian:stable-slim cat /proc/self/cgroup
```

The change is mostly about what the process can see, not about whether cgroup enforcement exists.

## Security Impact

The cgroup namespace is best understood as a **visibility-hardening layer**. By itself it will not stop a breakout if the container has writable cgroup mounts, broad capabilities, or a dangerous cgroup v1 environment. However, if the host cgroup namespace is shared, the process learns more about how the system is organized and may find it easier to line up host-relative cgroup paths with other observations.

On **cgroup v2**, the namespace starts to matter a bit more because delegation rules are tighter. If the hierarchy is mounted with `nsdelegate`, the kernel treats cgroup namespaces as delegation boundaries: ancestor control files are supposed to stay outside the delegatee's reach, and writes at the namespace root are restricted to delegation-safe files such as `cgroup.procs`, `cgroup.threads`, and `cgroup.subtree_control`. This still does not make the namespace an escape primitive by itself, but it changes what a compromised workload can inspect and where it can safely create sub-cgroups.

So while this namespace is not usually the star of container breakout writeups, it still contributes to the broader goal of minimizing host information leakage and constraining cgroup delegation.

## Abuse

The immediate abuse value is mostly reconnaissance. If the host cgroup namespace is shared, compare the visible paths and look for host-revealing hierarchy details:

```bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/mountinfo | grep cgroup
```

If writable cgroup paths are also exposed, combine that visibility with a search for dangerous legacy interfaces:

```bash
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
```

The namespace itself rarely gives instant escape, but it often makes the environment easier to map before testing cgroup-based abuse primitives.

A quick runtime reality check also helps prioritize the attack path. Docker exposes `--cgroupns=host|private`, while Podman supports `host`, `private`, `container:<id>`, and `ns:<path>`. On Podman specifically, the default is usually **`host` on cgroup v1** and **`private` on cgroup v2**, so simply identifying the cgroup version already tells you which namespace posture is more likely before you even inspect the full OCI config.

### Modern v2 Recon: Is This A Delegated Subtree?

On modern hosts the interesting question is often not `release_agent`, but whether the current process is sitting inside a delegated **cgroup v2** subtree with enough visibility or write access to build nested groups:

```bash
stat -fc %T /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cat /sys/fs/cgroup/cgroup.events 2>/dev/null
```

Useful interpretation:

- `cgroup2fs` means you are in the unified v2 hierarchy, so classic v1-only `release_agent` chains should stop being your first guess.
- `cgroup.controllers` shows which controllers are available from the parent and therefore what the current subtree could potentially fan out to children.
- `cgroup.subtree_control` shows which controllers are actually enabled for descendants.
- `cgroup.events` exposes `populated=0/1`, which is handy for watching whether a subtree has become empty, but it is **not** a host-code-execution primitive like v1 `release_agent`.

If you already have enough privilege to inspect another process namespace directly, compare views with:

```bash
nsenter -t <pid> -C -- bash
readlink /proc/self/ns/cgroup
cat /proc/self/cgroup
```

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
readlink /proc/self/ns/cgroup       # Namespace identifier for cgroup view
cat /proc/self/cgroup               # Visible cgroup paths from inside the workload
cat /proc/self/mountinfo | grep cgroup
stat -fc %T /sys/fs/cgroup          # cgroup2fs -> v2 unified hierarchy
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
mount | grep cgroup
```

What is interesting here:

- If the namespace identifier matches a host process you care about, the cgroup namespace may be shared.
- Host-revealing paths in `/proc/self/cgroup` or ancestor-rooted entries in `mountinfo` are useful reconnaissance even when they are not directly exploitable.
- If `cgroup2fs` is in use, focus on delegation, visible controllers, and writable subtrees rather than assuming old v1 primitives still exist.
- If cgroup mounts are also writable, the visibility question becomes much more important.

The cgroup namespace should be treated as a visibility-hardening layer rather than as a primary escape-prevention mechanism. Exposing host cgroup structure unnecessarily adds reconnaissance value for the attacker.

## References

- [Linux cgroup_namespaces(7)](https://man7.org/linux/man-pages/man7/cgroup_namespaces.7.html)
- [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html)

{{#include ../../../../../banners/hacktricks-training.md}}
