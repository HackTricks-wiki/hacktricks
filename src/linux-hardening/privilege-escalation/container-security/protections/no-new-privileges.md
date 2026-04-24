# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` is a kernel hardening feature that prevents a process from gaining more privilege across `execve()`. In practical terms, once the flag is set, executing a setuid binary, a setgid binary, or a file with Linux file capabilities does not grant extra privilege beyond what the process already had. In containerized environments, this is important because many privilege-escalation chains rely on finding an executable inside the image that changes privilege when launched.

From a defensive point of view, `no_new_privs` is not a substitute for namespaces, seccomp, or capability dropping. It is a reinforcement layer. It blocks a specific class of follow-up escalation after code execution has already been obtained. That makes it particularly valuable in environments where images contain helper binaries, package-manager artifacts, or legacy tools that would otherwise be dangerous when combined with partial compromise.

## Operation

The kernel flag behind this behavior is `PR_SET_NO_NEW_PRIVS`. Once it is set for a process, later `execve()` calls cannot increase privilege. The important detail is that the process can still run binaries; it simply cannot use those binaries to cross a privilege boundary that the kernel would otherwise honor.

The kernel behavior is also **inherited and irreversible**: once a task sets `no_new_privs`, the bit is inherited across `fork()`, `clone()`, and `execve()`, and cannot be unset later. This is useful in assessments because a single `NoNewPrivs: 1` on the container process usually means descendants should also stay in that mode unless you are looking at a completely different process tree.

In Kubernetes-oriented environments, `allowPrivilegeEscalation: false` maps to this behavior for the container process. In Docker and Podman style runtimes, the equivalent is usually enabled explicitly through a security option. At the OCI layer, the same concept appears as `process.noNewPrivileges`.

## Important Nuances

`no_new_privs` blocks **exec-time** privilege gain, not every privilege change. In particular:

- setuid and setgid transitions stop working across `execve()`
- file capabilities do not add to the permitted set on `execve()`
- LSMs such as AppArmor or SELinux do not relax constraints after `execve()`
- already-held privilege is still already-held privilege

That last point matters operationally. If the process already runs as root, already has a dangerous capability, or already has access to a powerful runtime API or writable host mount, setting `no_new_privs` does not neutralize those exposures. It only removes one common **next step** in a privilege-escalation chain.

Also note that the flag does not block privilege changes that do not depend on `execve()`. For example, a task that is already privileged enough may still call `setuid(2)` directly or receive a privileged file descriptor over a Unix socket. This is why `no_new_privs` should be read together with [seccomp](seccomp.md), capability sets, and namespace exposure instead of as a standalone answer.

## Lab

Inspect the current process state:

```bash
grep NoNewPrivs /proc/self/status
```

Compare that with a container where the runtime enables the flag:

```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```

On a hardened workload, the result should show `NoNewPrivs: 1`.

You can also demonstrate the actual effect against a setuid binary:

```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```

The point of the comparison is not that `su` is universally exploitable. It is that the same image can behave very differently depending on whether `execve()` is still allowed to cross a privilege boundary.

## Security Impact

If `no_new_privs` is absent, a foothold inside the container may still be upgraded through setuid helpers or binaries with file capabilities. If it is present, those post-exec privilege changes are cut off. The effect is especially relevant in broad base images that ship many utilities the application never needed in the first place.

There is also an important seccomp interaction. Unprivileged tasks generally need `no_new_privs` set before they can install a seccomp filter in filter mode. This is one reason hardened containers often show both `Seccomp` and `NoNewPrivs` enabled together. From an attacker perspective, seeing both usually means the environment was configured deliberately rather than accidentally.

## Misconfigurations

The most common problem is simply not enabling the control in environments where it would be compatible. In Kubernetes, leaving `allowPrivilegeEscalation` enabled is often the default operational mistake. In Docker and Podman, omitting the relevant security option has the same effect. Another recurring failure mode is assuming that because a container is "not privileged", exec-time privilege transitions are automatically irrelevant.

A more subtle Kubernetes pitfall is that `allowPrivilegeEscalation: false` is **not** honored the way people expect when the container is `privileged` or when it has `CAP_SYS_ADMIN`. The Kubernetes API documents that `allowPrivilegeEscalation` is effectively always true in those cases. In practice, this means the field should be treated as one signal in the final posture, not as a guarantee that the runtime ended up with `NoNewPrivs: 1`.

## Abuse

If `no_new_privs` is not set, the first question is whether the image contains binaries that can still raise privilege:

```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```

Interesting results include:

- `NoNewPrivs: 0`
- setuid helpers such as `su`, `mount`, `passwd`, or distribution-specific admin tools
- binaries with file capabilities that grant network or filesystem privileges

In a real assessment, these findings do not prove a working escalation by themselves, but they identify exactly the binaries worth testing next.

In Kubernetes, also verify that the YAML intent matches the kernel reality:

```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```

Interesting combinations include:

- `allowPrivilegeEscalation: false` in the Pod spec but `NoNewPrivs: 0` in the container
- `cap_sys_admin` present, which makes the Kubernetes field far less trustworthy
- `Seccomp: 0` and `NoNewPrivs: 0`, which usually indicates a broadly weakened runtime posture rather than a single isolated mistake

### Full Example: In-Container Privilege Escalation Through setuid

This control usually prevents **in-container privilege escalation** rather than host escape directly. If `NoNewPrivs` is `0` and a setuid helper exists, test it explicitly:

```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```

If a known setuid binary is present and functional, try launching it in a way that preserves the privilege transition:

```bash
/bin/su -c id 2>/dev/null
```

This does not by itself escape the container, but it can convert a low-privilege foothold inside the container into container-root, which often becomes the prerequisite for later host escape through mounts, runtime sockets, or kernel-facing interfaces.

## Checks

The goal of these checks is to establish whether exec-time privilege gain is blocked and whether the image still contains helpers that would matter if it is not.

```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```

What is interesting here:

- `NoNewPrivs: 1` is usually the safer result.
- `NoNewPrivs: 0` means setuid and file-cap based escalation paths remain relevant.
- `NoNewPrivs: 1` plus `Seccomp: 2` is a common sign of a more intentional hardening posture.
- A Kubernetes manifest that says `allowPrivilegeEscalation: false` is useful, but the kernel status is the ground truth.
- A minimal image with few or no setuid/file-cap binaries gives an attacker fewer post-exploitation options even when `no_new_privs` is missing.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges=true`; daemon-wide default also exists via `dockerd --no-new-privileges` | omitting the flag, `--privileged` |
| Podman | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | omitting the option, `--privileged` |
| Kubernetes | Controlled by workload policy | `allowPrivilegeEscalation: false` requests the effect, but `privileged: true` and `CAP_SYS_ADMIN` keep it effectively true | `allowPrivilegeEscalation: true`, `privileged: true`, adding `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes workload settings / OCI `process.noNewPrivileges` | Usually inherited from the Pod security context and translated into OCI runtime config | same as Kubernetes row |

This protection is often absent simply because nobody turned it on, not because the runtime lacks support for it.

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
