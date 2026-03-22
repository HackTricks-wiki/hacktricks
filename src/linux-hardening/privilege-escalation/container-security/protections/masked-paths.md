# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths are runtime protections that hide especially sensitive kernel-facing filesystem locations from the container by bind-mounting over them or otherwise making them inaccessible. The purpose is to prevent a workload from interacting directly with interfaces that ordinary applications do not need, especially inside procfs.

This matters because many container escapes and host-impacting tricks start by reading or writing special files under `/proc` or `/sys`. If those locations are masked, the attacker loses direct access to a useful part of the kernel control surface even after gaining code execution inside the container.

## Operation

Runtimes commonly mask selected paths such as:

- `/proc/kcore`
- `/proc/keys`
- `/proc/latency_stats`
- `/proc/timer_list`
- `/proc/sched_debug`
- `/sys/firmware`

The exact list depends on the runtime and host configuration. The important property is that the path becomes inaccessible or replaced from the container's point of view even though it still exists on the host.

## Lab

Inspect the masked-path configuration exposed by Docker:

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'
```

Inspect the actual mount behavior inside the workload:

```bash
mount | grep -E '/proc|/sys'
ls -ld /proc/kcore /proc/keys /sys/firmware 2>/dev/null
```

## Security Impact

Masking does not create the main isolation boundary, but it removes several high-value post-exploitation targets. Without masking, a compromised container may be able to inspect kernel state, read sensitive process or keying information, or interact with procfs/sysfs objects that should never have been visible to the application.

## Misconfigurations

The main mistake is unmasking broad classes of paths for convenience or debugging. In Podman this may appear as `--security-opt unmask=ALL` or targeted unmasking. In Kubernetes, overly broad proc exposure may appear through `procMount: Unmasked`. Another serious problem is exposing host `/proc` or `/sys` through a bind mount, which bypasses the idea of a reduced container view entirely.

## Abuse

If masking is weak or absent, start by identifying which sensitive procfs/sysfs paths are directly reachable:

```bash
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null   # Check whether paths that are usually masked are accessible at all
mount | grep -E '/proc|/sys'                                                # Review whether procfs/sysfs mounts look container-scoped or suspiciously host-like
```

If a supposedly masked path is accessible, inspect it carefully:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
cat /proc/keys 2>/dev/null | head         # In-kernel keyring information; may expose keys, key descriptions, or service relationships
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

What these commands can reveal:

- `/proc/timer_list` can expose host timer and scheduler data. This is mostly a reconnaissance primitive, but it confirms that the container can read kernel-facing information that is normally hidden.
- `/proc/keys` is much more sensitive. Depending on the host configuration, it may reveal keyring entries, key descriptions, and relationships between host services using the kernel keyring subsystem.
- `/sys/firmware` helps identify boot mode, firmware interfaces, and platform details that are useful for host fingerprinting and for understanding whether the workload is seeing host-level state.
- `/proc/config.gz` may reveal the running kernel configuration, which is valuable for matching public kernel exploit prerequisites or understanding why a specific feature is reachable.
- `/proc/sched_debug` exposes scheduler state and often bypasses the intuitive expectation that the PID namespace should hide unrelated process information completely.

Interesting results include direct reads from those files, evidence that the data belongs to the host rather than to a constrained container view, or access to other procfs/sysfs locations that are commonly masked by default.

## Checks

The point of these checks is to determine which paths the runtime intentionally hid and whether the current workload still sees a reduced kernel-facing filesystem.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
ls -ld /proc/kcore /proc/keys /proc/timer_list /sys/firmware 2>/dev/null
```

What is interesting here:

- A long masked-path list is normal in hardened runtimes.
- Missing masking on sensitive procfs entries deserves closer inspection.
- If a sensitive path is accessible and the container also has strong capabilities or broad mounts, the exposure matters more.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker defines a default masked path list | exposing host proc/sys mounts, `--privileged` |
| Podman | Enabled by default | Podman applies default masked paths unless unmasked manually | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | Inherits runtime defaults | Uses the underlying runtime's masking behavior unless Pod settings weaken proc exposure | `procMount: Unmasked`, privileged workload patterns, broad host mounts |
| containerd / CRI-O under Kubernetes | Runtime default | Usually applies OCI/runtime masked paths unless overridden | direct runtime config changes, same Kubernetes weakening paths |

Masked paths are usually present by default. The main operational problem is not absence from the runtime, but deliberate unmasking or host bind mounts that negate the protection.
{{#include ../../../../banners/hacktricks-training.md}}
