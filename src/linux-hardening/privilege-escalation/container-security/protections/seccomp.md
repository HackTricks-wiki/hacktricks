# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## Overview

**seccomp** is the mechanism that lets the kernel apply a filter to the syscalls a process may invoke. In containerized environments, seccomp is normally used in filter mode so that the process is not simply marked "restricted" in a vague sense, but is instead subject to a concrete syscall policy. This matters because many container breakouts require reaching very specific kernel interfaces. If the process cannot successfully invoke the relevant syscalls, a large class of attacks disappears before any namespace or capability nuance even becomes relevant.

The key mental model is simple: namespaces decide **what the process can see**, capabilities decide **which privileged actions the process is nominally allowed to attempt**, and seccomp decides **whether the kernel will even accept the syscall entry point for the attempted action**. This is why seccomp frequently prevents attacks that would otherwise look possible based on capabilities alone.

## Security Impact

A lot of dangerous kernel surface is reachable only through a relatively small set of syscalls. Examples that repeatedly matter in container hardening include `mount`, `unshare`, `clone` or `clone3` with particular flags, `bpf`, `ptrace`, `keyctl`, and `perf_event_open`. An attacker who can reach those syscalls may be able to create new namespaces, manipulate kernel subsystems, or interact with attack surface that a normal application container does not need at all.

This is why default runtime seccomp profiles are so important. They are not merely "extra defense". In many environments they are the difference between a container that can exercise a broad portion of kernel functionality and one that is constrained to a syscall surface closer to what the application genuinely needs.

## Modes And Filter Construction

seccomp historically had a strict mode in which only a tiny syscall set remained available, but the mode relevant to modern container runtimes is seccomp filter mode, often called **seccomp-bpf**. In this model, the kernel evaluates a filter program that decides whether a syscall should be allowed, denied with an errno, trapped, logged, or kill the process. Container runtimes use this mechanism because it is expressive enough to block broad classes of dangerous syscalls while still allowing normal application behavior.

Two low-level examples are useful because they make the mechanism concrete rather than magical. Strict mode demonstrates the old "only a minimal syscall set survives" model:

```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
  int output = open("output.txt", O_WRONLY);
  const char *val = "test";
  prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
  write(output, val, strlen(val) + 1);
  open("output.txt", O_RDONLY);
}
```

The final `open` causes the process to be killed because it is not part of strict mode's minimal set.

A libseccomp filter example shows the modern policy model more clearly:

```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
  seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
    SCMP_A0(SCMP_CMP_EQ, 1),
    SCMP_A2(SCMP_CMP_LE, 512));
  seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
    SCMP_A0(SCMP_CMP_NE, 1));
  seccomp_load(ctx);
  seccomp_release(ctx);
  printf("pid=%d\n", getpid());
}
```

This style of policy is what most readers should picture when they think about runtime seccomp profiles.

## Lab

A simple way to confirm that seccomp is active in a container is:

```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```

You can also try an operation that default profiles commonly restrict:

```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```

If the container is running under a normal default seccomp profile, `unshare`-style operations are often blocked. This is a useful demonstration because it shows that even if the userspace tool exists inside the image, the kernel path it needs may still be unavailable.
If the container is running under a normal default seccomp profile, `unshare`-style operations are often blocked even when the userspace tool exists inside the image.

To inspect the process status more generally, run:

```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```

## Runtime Usage

Docker supports both default and custom seccomp profiles and allows administrators to disable them with `--security-opt seccomp=unconfined`. Podman has similar support and often pairs seccomp with rootless execution in a very sensible default posture. Kubernetes exposes seccomp through workload configuration, where `RuntimeDefault` is usually the sane baseline and `Unconfined` should be treated as an exception requiring justification rather than as a convenience toggle.

In containerd and CRI-O based environments, the exact path is more layered, but the principle is the same: the higher-level engine or orchestrator decides what should happen, and the runtime eventually installs the resulting seccomp policy for the container process. The outcome still depends on the final runtime configuration that reaches the kernel.

### Custom Policy Example

Docker and similar engines can load a custom seccomp profile from JSON. A minimal example that denies `chmod` while allowing everything else looks like this:

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "name": "chmod",
      "action": "SCMP_ACT_ERRNO"
    }
  ]
}
```

Applied with:

```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```

The command fails with `Operation not permitted`, demonstrating that the restriction comes from the syscall policy rather than from ordinary file permissions alone. In real hardening, allowlists are generally stronger than permissive defaults with a small blacklist.

## Misconfigurations

The bluntest mistake is to set seccomp to **unconfined** because an application failed under the default policy. This is common during troubleshooting and very dangerous as a permanent fix. Once the filter is gone, many syscall-based breakout primitives become reachable again, especially when powerful capabilities or host namespace sharing are also present.

Another frequent problem is the use of a **custom permissive profile** that was copied from some blog or internal workaround without being reviewed carefully. Teams sometimes retain almost all dangerous syscalls simply because the profile was built around "stop the app from breaking" rather than "grant only what the app actually needs". A third misconception is to assume seccomp is less important for non-root containers. In reality, plenty of kernel attack surface remains relevant even when the process is not UID 0.

## Abuse

If seccomp is absent or badly weakened, an attacker may be able to invoke namespace-creation syscalls, expand the reachable kernel attack surface through `bpf` or `perf_event_open`, abuse `keyctl`, or combine those syscall paths with dangerous capabilities such as `CAP_SYS_ADMIN`. In many real attacks, seccomp is not the only missing control, but its absence shortens the exploit path dramatically because it removes one of the few defenses that can stop a risky syscall before the rest of the privilege model even comes into play.

The most useful practical test is to try the exact syscall families that default profiles usually block. If they suddenly work, the container posture has changed a lot:

```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```

If `CAP_SYS_ADMIN` or another strong capability is present, test whether seccomp is the only missing barrier before mount-based abuse:

```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```

On some targets, the immediate value is not full escape but information gathering and kernel attack-surface expansion. These commands help determine whether especially sensitive syscall paths are reachable:

```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```

If seccomp is absent and the container is also privileged in other ways, that is when it makes sense to pivot into the more specific breakout techniques already documented in the legacy container-escape pages.

### Full Example: seccomp Was The Only Thing Blocking `unshare`

On many targets, the practical effect of removing seccomp is that namespace-creation or mount syscalls suddenly start working. If the container also has `CAP_SYS_ADMIN`, the following sequence may become possible:

```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
  mount -t tmpfs tmpfs /tmp/nsroot &&
  mkdir -p /tmp/nsroot/proc &&
  mount -t proc proc /tmp/nsroot/proc &&
  mount | grep /tmp/nsroot
'
```

By itself this is not yet a host escape, but it demonstrates that seccomp was the barrier preventing mount-related exploitation.

### Full Example: seccomp Disabled + cgroup v1 `release_agent`

If seccomp is disabled and the container can mount cgroup v1 hierarchies, the `release_agent` technique from the cgroups section becomes reachable:

```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
  mkdir /tmp/c
  mount -t cgroup -o memory none /tmp/c
  echo 1 > /tmp/c/notify_on_release
  echo /proc/self/exe > /tmp/c/release_agent
  (sleep 1; echo 0 > /tmp/c/cgroup.procs) &
  while true; do sleep 1; done
'
```

This is not a seccomp-only exploit. The point is that once seccomp is unconfined, syscall-heavy breakout chains that were previously blocked may start working exactly as written.

## Checks

The purpose of these checks is to establish whether seccomp is active at all, whether `no_new_privs` accompanies it, and whether the runtime configuration shows seccomp being disabled explicitly.

```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```

What is interesting here:

- A non-zero `Seccomp` value means filtering is active; `0` usually means no seccomp protection.
- If the runtime security options include `seccomp=unconfined`, the workload has lost one of its most useful syscall-level defenses.
- `NoNewPrivs` is not seccomp itself, but seeing both together usually indicates a more careful hardening posture than seeing neither.

If a container already has suspicious mounts, broad capabilities, or shared host namespaces, and seccomp is also unconfined, that combination should be treated as a major escalation signal. The container may still not be trivially breakable, but the number of kernel entry points available to the attacker has increased sharply.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Usually enabled by default | Uses Docker's built-in default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Usually enabled by default | Applies the runtime default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **Not guaranteed by default** | If `securityContext.seccompProfile` is unset, the default is `Unconfined` unless the kubelet enables `--seccomp-default`; `RuntimeDefault` or `Localhost` must otherwise be set explicitly | `securityContext.seccompProfile.type: Unconfined`, leaving seccomp unset on clusters without `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes node and Pod settings | Runtime profile is used when Kubernetes asks for `RuntimeDefault` or when kubelet seccomp defaulting is enabled | Same as Kubernetes row; direct CRI/OCI configuration can also omit seccomp entirely |

The Kubernetes behavior is the one that most often surprises operators. In many clusters, seccomp is still absent unless the Pod requests it or the kubelet is configured to default to `RuntimeDefault`.
{{#include ../../../../banners/hacktricks-training.md}}
