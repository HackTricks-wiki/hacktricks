# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` is a kernel hardening feature that prevents a process from gaining more privilege across `execve()`. In practical terms, once the flag is set, executing a setuid binary, a setgid binary, or a file with Linux file capabilities does not grant extra privilege beyond what the process already had. In containerized environments, this is important because many privilege-escalation chains rely on finding an executable inside the image that changes privilege when launched.

From a defensive point of view, `no_new_privs` is not a substitute for namespaces, seccomp, or capability dropping. It is a reinforcement layer. It blocks a specific class of follow-up escalation after code execution has already been obtained. That makes it particularly valuable in environments where images contain helper binaries, package-manager artifacts, or legacy tools that would otherwise be dangerous when combined with partial compromise.

## Operation

The kernel flag behind this behavior is `PR_SET_NO_NEW_PRIVS`. Once it is set for a process, later `execve()` calls cannot increase privilege. The important detail is that the process can still run binaries; it simply cannot use those binaries to cross a privilege boundary that the kernel would otherwise honor.

In Kubernetes-oriented environments, `allowPrivilegeEscalation: false` maps to this behavior for the container process. In Docker and Podman style runtimes, the equivalent is usually enabled explicitly through a security option.

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

## Security Impact

If `no_new_privs` is absent, a foothold inside the container may still be upgraded through setuid helpers or binaries with file capabilities. If it is present, those post-exec privilege changes are cut off. The effect is especially relevant in broad base images that ship many utilities the application never needed in the first place.

## Misconfigurations

The most common problem is simply not enabling the control in environments where it would be compatible. In Kubernetes, leaving `allowPrivilegeEscalation` enabled is often the default operational mistake. In Docker and Podman, omitting the relevant security option has the same effect. Another recurring failure mode is assuming that because a container is "not privileged", exec-time privilege transitions are automatically irrelevant.

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
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```

What is interesting here:

- `NoNewPrivs: 1` is usually the safer result.
- `NoNewPrivs: 0` means setuid and file-cap based escalation paths remain relevant.
- A minimal image with few or no setuid/file-cap binaries gives an attacker fewer post-exploitation options even when `no_new_privs` is missing.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges=true` | omitting the flag, `--privileged` |
| Podman | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | omitting the option, `--privileged` |
| Kubernetes | Controlled by workload policy | `allowPrivilegeEscalation: false` enables the effect; many workloads still leave it enabled | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes workload settings | Usually inherited from the Pod security context | same as Kubernetes row |

This protection is often absent simply because nobody turned it on, not because the runtime lacks support for it.
{{#include ../../../../banners/hacktricks-training.md}}
