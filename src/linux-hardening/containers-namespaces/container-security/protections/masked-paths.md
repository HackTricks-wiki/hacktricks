# Masked Paths

{{#include ../../../../banners/hacktricks-training.md}}

Masked paths are runtime protections that hide especially sensitive kernel-facing filesystem locations from the container by bind-mounting over them or otherwise making them inaccessible. The OCI runtime specification defines `maskedPaths` as absolute paths that must not be readable inside the container. <sup>[[1]](#references)</sup>

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

A listed path is not necessarily readable: runc can mask a file with a `/dev/null` bind mount and a directory with a read-only empty tmpfs. Check the exact mountpoint, not just whether `ls` succeeds. <sup>[[4]](#references)</sup>

## Security Impact

Masking does not create the main isolation boundary, but it removes several high-value post-exploitation targets. Without masking, a compromised container may be able to inspect kernel state, read sensitive process or keying information, or interact with procfs/sysfs objects that should never have been visible to the application.

## Misconfigurations

The main mistake is unmasking broad classes of paths for convenience or debugging. In Podman this may appear as `--security-opt unmask=ALL` or targeted unmasking. <sup>[[2]](#references)</sup> In Kubernetes, overly broad proc exposure may appear through `procMount: Unmasked`; current Kubernetes requires `spec.hostUsers: false` (a user namespace) for this setting, whereas versions 1.12–1.29 did not enforce that requirement. <sup>[[3]](#references)</sup> Another serious problem is exposing host `/proc` or `/sys` through a bind mount, which bypasses the idea of a reduced container view entirely.

## Abuse

If masking is weak or absent, start by identifying which sensitive procfs/sysfs paths are directly reachable:

```bash
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
mount | grep -E '/proc|/sys'  # Review the wider procfs/sysfs layout
```

If a supposedly masked path is accessible, inspect it carefully:

```bash
head -n 20 /proc/timer_list 2>/dev/null   # Scheduler / timer internals, useful for host fingerprinting and confirming kernel data exposure
head /proc/keys 2>/dev/null             # View-permitted key metadata, not key payloads
ls -la /sys/firmware 2>/dev/null          # Firmware / boot environment metadata; useful for host fingerprinting and low-level platform recon
zcat /proc/config.gz 2>/dev/null | head   # Kernel build configuration; useful to confirm enabled subsystems and exploit preconditions
head -n 50 /proc/sched_debug 2>/dev/null  # Scheduler and process metadata; may reveal host tasks and cgroup relationships
```

What these commands can reveal:

- `/proc/timer_list` can expose host timer and scheduler data. This is mostly a reconnaissance primitive, but it confirms that the container can read kernel-facing information that is normally hidden.
- `/proc/keys` lists metadata only for keys the reader has **view** permission for, subject to LSM checks. It can reveal key types and descriptions, but does not dump key payloads. <sup>[[6]](#references)</sup>
- `/sys/firmware` helps identify boot mode, firmware interfaces, and platform details that are useful for host fingerprinting and for understanding whether the workload is seeing host-level state.
- `/proc/config.gz` may reveal the running kernel configuration, which is valuable for matching public kernel exploit prerequisites or understanding why a specific feature is reachable.
- `/proc/sched_debug` exposes scheduler state and often bypasses the intuitive expectation that the PID namespace should hide unrelated process information completely.

Interesting results include direct reads from those files, evidence that the data belongs to the host rather than to a constrained container view, or access to other procfs/sysfs locations that are commonly masked by default.

### Mask-source race during container startup

In vulnerable runc implementations, file masks depend on the container's `/dev/null` inode. An attacker who can arrange concurrent containers with shared mounts, including parallel BuildKit steps, can race startup and remove `/dev/null` before runc binds it over masked procfs files. The runtime then treats the missing **source** as if a mask destination were absent and silently skips those file masks. The failure depends on a race during runtime setup; removing `/dev/null` after startup does not undo an already installed mask. <sup>[[4]](#references)</sup>

After a controlled test, compare the requested mask list with exact mountpoints inside the new container. <sup>[[4]](#references)</sup> `findmnt -M` checks the named mountpoint rather than falling back to a parent mount; if `findmnt` is absent, inspect `/proc/self/mountinfo`. <sup>[[5]](#references)</sup> An `ls` success or an empty `cat` cannot prove the mask is absent. <sup>[[4]](#references)</sup>

Use the [checks below](#checks) to compare the requested masks with exact mounts in the new container.

A skipped file mask may expose procfs data if normal permissions and LSM policy allow it. It does **not** by itself make `/proc/sys` writable: that is a separate [read-only-path](read-only-paths.md) control. The distinct `/dev/null` symlink substitution that can redirect a bind mount to a writable procfs target is covered under the [PID-namespace runtime race](namespaces/pid-namespace.md#maskedpaths-race-to-host-procfs). <sup>[[4]](#references)</sup>

## Checks

The point of these checks is to determine which paths the runtime intentionally hid and whether the current workload still sees a reduced kernel-facing filesystem.

```bash
docker inspect <container> | jq '.[0].HostConfig.MaskedPaths'   # Runtime-declared masked paths
mount | grep -E '/proc|/sys'                                    # Actual procfs/sysfs mount layout
for p in /proc/kcore /proc/keys /proc/timer_list /sys/firmware; do
  printf "%s: " "$p"
  findmnt -M "$p" -n -o TARGET,SOURCE,FSTYPE,OPTIONS
done
```

Use an exact-mount check because a masked file can still exist and a read can return an empty result from `/dev/null`. An absent mountpoint is a finding to investigate, not proof of readable host data by itself. <sup>[[4]](#references)[[5]](#references)</sup>

What is interesting here:

- A long masked-path list is normal in hardened runtimes.
- Missing masking on sensitive procfs entries deserves closer inspection.
- If a sensitive path is accessible and the container also has strong capabilities or broad mounts, the exposure matters more.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker defines a default masked path list | exposing host proc/sys mounts, `--privileged` |
| Podman | Enabled by default | Podman applies default masked paths unless unmasked manually | `--security-opt unmask=ALL`, targeted unmasking, `--privileged` |
| Kubernetes | Inherits runtime defaults | Uses the underlying runtime's masking behavior unless Pod settings weaken proc exposure | `procMount: Unmasked` (requires `hostUsers: false` on current releases), privileged workload patterns, broad host mounts |
| containerd / CRI-O under Kubernetes | Runtime default | Usually applies OCI/runtime masked paths unless overridden | direct runtime config changes, same Kubernetes weakening paths |

Masked paths are usually present by default. The main operational problem is not absence from the runtime, but deliberate unmasking or host bind mounts that negate the protection.

## References

- [1] [Open Container Initiative - Linux container configuration: Masked Paths](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)
- [2] [Podman documentation - `podman run` security options](https://docs.podman.io/en/latest/markdown/podman-run.1.html#security-opt-option)
- [3] [Kubernetes Documentation - ProcMount](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-the-proc-mount-type-for-a-container)
- [4] [runc advisory: masked-path mount source race](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [5] [findmnt(8) manual](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [6] [keyrings(7) manual](https://man7.org/linux/man-pages/man7/keyrings.7.html)

{{#include ../../../../banners/hacktricks-training.md}}
