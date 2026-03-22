# Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

The most important idea in container hardening is that there is no single control called "container security". What people call container isolation is really the result of several Linux security and resource-management mechanisms working together. If documentation describes only one of them, readers tend to overestimate its strength. If documentation lists all of them without explaining how they interact, readers get a catalog of names but no real model. This section tries to avoid both mistakes.

At the center of the model are **namespaces**, which isolate what the workload can see. They give the process a private or partially private view of filesystem mounts, PIDs, networking, IPC objects, hostnames, user/group mappings, cgroup paths, and some clocks. But namespaces alone do not decide what a process is allowed to do. That is where the next layers enter.

**cgroups** govern resource usage. They are not primarily an isolation boundary in the same sense as mount or PID namespaces, but they are crucial operationally because they constrain memory, CPU, PIDs, I/O, and device access. They also have security relevance because historical breakout techniques abused writable cgroup features, especially in cgroup v1 environments.

**Capabilities** split the old all-powerful root model into smaller privilege units. This is fundamental for containers because many workloads still run as UID 0 inside the container. The question is therefore not merely "is the process root?", but rather "which capabilities survived, inside which namespaces, under which seccomp and MAC restrictions?" That is why a root process in one container can be relatively constrained while a root process in another container can be almost indistinguishable from host root in practice.

**seccomp** filters syscalls and reduces the kernel attack surface exposed to the workload. This is often the mechanism that blocks obviously dangerous calls such as `unshare`, `mount`, `keyctl`, or other syscalls used in breakout chains. Even if a process has a capability that would otherwise permit an operation, seccomp may still block the syscall path before the kernel fully processes it.

**AppArmor** and **SELinux** add Mandatory Access Control on top of normal filesystem and privilege checks. These are particularly important because they continue to matter even when a container has more capabilities than it should. A workload may possess the theoretical privilege to attempt an action but still be prevented from carrying it out because its label or profile forbids access to the relevant path, object, or operation.

Finally, there are additional hardening layers that receive less attention but regularly matter in real attacks: `no_new_privs`, masked procfs paths, read-only system paths, read-only root filesystems, and careful runtime defaults. These mechanisms often stop the "last mile" of a compromise, especially when an attacker tries to turn code execution into a broader privilege gain.

The rest of this folder explains each of these mechanisms in more detail, including what the kernel primitive actually does, how to observe it locally, how common runtimes use it, and how operators accidentally weaken it.

## Read Next

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

Many real escapes also depend on what host content was mounted into the workload, so after reading the core protections it is useful to continue with:

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
