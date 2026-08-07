# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

**seccomp** 是一种机制，允许 kernel 对进程可以调用的 syscall 应用过滤器。在容器化环境中，seccomp 通常以 filter mode 使用，使进程不是被笼统地标记为“受限”，而是受到具体 syscall policy 的约束。这一点很重要，因为许多 container breakout 都需要访问非常特定的 kernel interface。如果进程无法成功调用相关 syscall，那么大量攻击会在 namespace 或 capability 细节开始发挥作用之前就被阻断。

核心理解模型很简单：namespace 决定**进程可以看到什么**，capability 决定**进程名义上被允许尝试哪些特权操作**，而 seccomp 决定**kernel 是否甚至会接受该操作所尝试进入的 syscall entry point**。因此，seccomp 经常能够阻止那些仅根据 capability 看起来原本可行的攻击。

## 安全影响

许多危险的 kernel attack surface 只能通过相对较少的一组 syscall 访问。在 container hardening 中反复重要的示例包括 `mount`、`unshare`、带有特定 flag 的 `clone` 或 `clone3`、`bpf`、`ptrace`、`keyctl` 以及 `perf_event_open`。能够访问这些 syscall 的攻击者，可能可以创建新的 namespace、操纵 kernel subsystem，或与普通 application container 完全不需要的 attack surface 交互。

这正是默认 runtime seccomp profile 如此重要的原因。它们不仅仅是“额外防御”。在许多环境中，它们决定了一个 container 是能够使用 kernel functionality 的广泛部分，还是只能使用更接近应用实际需求的 syscall surface。

## 模式与 Filter 构建

seccomp 历史上具有一种 strict mode，在该模式下只有极少的一组 syscall 仍然可用，但与现代 container runtime 相关的模式是 seccomp filter mode，通常称为 **seccomp-bpf**。在这种模型中，kernel 会评估一个 filter program，由它决定是否允许 syscall、以 errno 拒绝、进行 trap、记录日志，或 kill 进程。<sup>[[1]](#references)</sup> Container runtime 使用这一机制，是因为它足够灵活，能够阻止大范围的危险 syscall，同时仍允许正常的应用行为。

下面两个低级示例很有用，因为它们使这一机制变得具体，而不是看起来神秘莫测。Strict mode 展示了旧的“只有最小 syscall 集合能够保留”的模型：
```c
#include <fcntl.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void) {
int output = open("output.txt", O_WRONLY);
const char *val = "test";
prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT);
write(output, val, strlen(val) + 1);
open("output.txt", O_RDONLY);
}
```
最后的 `open` 会导致进程被终止，因为它不属于 strict mode 的最小 syscall 集合。

一个 libseccomp filter 示例更清晰地展示了现代 policy model：
```c
#include <errno.h>
#include <seccomp.h>
#include <stdio.h>
#include <unistd.h>

int main(void) {
scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(getpid), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 2,
SCMP_A0(SCMP_CMP_EQ, 1),
SCMP_A2(SCMP_CMP_LE, 512));
seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EBADF), SCMP_SYS(write), 1,
SCMP_A0(SCMP_CMP_NE, 1));
seccomp_load(ctx);
seccomp_release(ctx);
printf("pid=%d\n", getpid());
}
```
这种 policy 是大多数读者想到 runtime seccomp profiles 时应联想到的形式。

## 实验

确认 container 中 seccomp 已启用的一种简单方法是：
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
你还可以尝试执行默认配置通常会限制的操作：
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
如果容器在正常的默认 seccomp profile 下运行，`unshare` 风格的操作通常会被阻止。这是一个很有用的演示，因为它表明，即使 image 中存在相应的 userspace 工具，它所需的 kernel 路径仍可能不可用。
如果容器在正常的默认 seccomp profile 下运行，即使 image 中存在 userspace 工具，`unshare` 风格的操作也通常会被阻止。

要更一般地检查进程状态，请运行：
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime 使用

Docker 支持默认和 custom seccomp profiles，并允许管理员通过 `--security-opt seccomp=unconfined` 禁用它们。<sup>[[2]](#references)</sup> Podman 也提供类似支持，并且通常将 seccomp 与 rootless execution 配合使用，形成非常合理的默认安全姿态。Kubernetes 通过 workload configuration 提供 seccomp，其中 `RuntimeDefault` 通常是合理的基线，而 `Unconfined` 应被视为需要说明理由的例外，而不是一个图方便的开关。<sup>[[3]](#references)</sup>

在基于 containerd 和 CRI-O 的环境中，具体路径会更加分层，但原则相同：更高层的 engine 或 orchestrator 决定应采取的措施，而 runtime 最终会为 container process 安装由此产生的 seccomp policy。最终结果仍取决于传递到 kernel 的最终 runtime configuration。

### Custom Policy 示例

Docker 和类似的 engines 可以从 JSON 加载 custom seccomp profile。下面是一个在允许其他所有操作的同时拒绝 `chmod` 的最小示例：
```json
{
"defaultAction": "SCMP_ACT_ALLOW",
"syscalls": [
{
"name": "chmod",
"action": "SCMP_ACT_ERRNO"
}
]
}
```
应用于：
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
该命令因 `Operation not permitted` 而失败，这表明限制来自 syscall policy，而不仅仅是普通的文件权限。在实际 hardening 中，allowlists 通常比带有少量 blacklist 的宽松默认配置更强。

## Misconfigurations

最直接的错误，是因为应用在默认 policy 下运行失败，就将 seccomp 设置为 **unconfined**。这在故障排查期间很常见，但作为永久修复方案非常危险。过滤器一旦被移除，许多基于 syscall 的 breakout primitive 将重新变得可用，尤其是在同时存在强大 capabilities 或共享 host namespace 的情况下。

另一个常见问题，是使用从某篇 blog 或内部 workaround 中复制而来、未经仔细审查的 **custom permissive profile**。团队有时会保留几乎所有危险 syscall，仅仅因为 profile 的目标是“阻止应用崩溃”，而不是“只授予应用实际需要的权限”。第三个误解，是认为 seccomp 对 non-root containers 不那么重要。实际上，即使进程不是 UID 0，仍有大量 kernel attack surface 具有现实意义。

## Abuse

如果 seccomp 缺失或被严重削弱，attacker 可能能够调用 namespace-creation syscalls，通过 `bpf` 或 `perf_event_open` 扩大可触达的 kernel attack surface，滥用 `keyctl`，或者将这些 syscall 路径与 `CAP_SYS_ADMIN` 等危险 capabilities 结合起来。在许多真实攻击中，seccomp 并不是唯一缺失的控制措施，但它的缺失会显著缩短 exploit path，因为它移除了少数能够在其余 privilege model 介入之前阻止高风险 syscall 的防御机制之一。

最实用的测试方法，是尝试 default profiles 通常会阻止的确切 syscall families。如果它们突然能够正常工作，就说明 container posture 已发生很大变化：
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
如果存在 `CAP_SYS_ADMIN` 或其他强大的 capability，请测试 seccomp 是否是阻止 mount-based abuse 的唯一屏障：
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
在某些目标上，直接收益并非完全逃逸，而是信息收集和扩大内核攻击面。这些命令有助于确定是否能够访问尤其敏感的 syscall 路径：
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
如果 seccomp 不存在，且容器在其他方面也具有特权，那么此时就适合转向 legacy container-escape 页面中已经记录的更具体的 breakout techniques。

### 完整示例：seccomp 是唯一阻止 `unshare` 的因素

在许多目标上，移除 seccomp 的实际效果是，namespace-creation 或 mount syscalls 突然开始正常工作。如果容器还具有 `CAP_SYS_ADMIN`，则以下序列可能变得可行：
```bash
grep Seccomp /proc/self/status
capsh --print | grep cap_sys_admin
mkdir -p /tmp/nsroot
unshare -m sh -c '
mount -t tmpfs tmpfs /tmp/nsroot &&
mkdir -p /tmp/nsroot/proc &&
mount -t proc proc /tmp/nsroot/proc &&
mount | grep /tmp/nsroot
'
```
单独来看，这还不能算是 host escape，但它证明了 seccomp 是阻止 mount 相关利用的屏障。

### 完整示例：禁用 seccomp + cgroup v1 `release_agent`

如果 seccomp 被禁用，且 container 可以挂载 cgroup v1 层级结构，那么 cgroups 部分介绍的 `release_agent` technique 就可以被利用：
```bash
grep Seccomp /proc/self/status
mount | grep cgroup
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
这不是一个仅依赖 seccomp 的 exploit。重点在于，一旦 seccomp 处于 unconfined 状态，之前被阻止的、依赖大量 syscall 的 breakout chain 可能会开始按原样运行。

## 检查

这些检查旨在确认 seccomp 是否处于 active 状态、是否同时启用了 `no_new_privs`，以及 runtime configuration 是否明确显示 seccomp 已被禁用。
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
这里有什么值得注意的：

- 非零的 `Seccomp` 值表示过滤处于启用状态；`0` 通常表示没有 seccomp protection。
- 如果 runtime security options 包含 `seccomp=unconfined`，说明该 workload 已失去最有用的 syscall-level defenses 之一。
- `NoNewPrivs` 本身不是 seccomp，但同时看到这两项，通常说明其 hardening posture 比两者都没有时更加谨慎。

如果一个 container 已经存在可疑 mounts、宽泛 capabilities 或共享的 host namespaces，同时 seccomp 也是 unconfined，则应将这种组合视为一个重大的 escalation signal。该 container 可能仍然无法被轻易攻破，但攻击者可用的 kernel entry points 数量已经大幅增加。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 通常默认启用 | 使用 Docker 内置的 default seccomp profile，除非被覆盖 | `--security-opt seccomp=unconfined`、`--security-opt seccomp=/path/profile.json`、`--privileged` |
| Podman | 通常默认启用 | 使用 runtime default seccomp profile，除非被覆盖 | `--security-opt seccomp=unconfined`、`--security-opt seccomp=profile.json`、`--seccomp-policy=image`、`--privileged` |
| Kubernetes | **默认不保证启用** | 如果未设置 `securityContext.seccompProfile`，则默认值为 `Unconfined`，除非 kubelet 启用了 `--seccomp-default`；否则必须显式设置 `RuntimeDefault` 或 `Localhost` | `securityContext.seccompProfile.type: Unconfined`、在未启用 `seccompDefault` 的 clusters 中不设置 seccomp、`privileged: true` |
| containerd / CRI-O under Kubernetes | 遵循 Kubernetes node 和 Pod 设置 | 当 Kubernetes 请求 `RuntimeDefault`，或 kubelet 启用了 seccomp defaulting 时，使用 runtime profile | 与 Kubernetes 行相同；直接的 CRI/OCI 配置也可能完全省略 seccomp |

Kubernetes 的行为是最常让 operators 感到意外的情况。在许多 clusters 中，除非 Pod 请求启用 seccomp，或 kubelet 被配置为默认使用 `RuntimeDefault`，否则 seccomp 仍然处于缺失状态。<sup>[[3]](#references)</sup>

## References

- [1] [Linux kernel documentation: Seccomp BPF (SECure COMPuting with filters)](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [2] [Docker Docs: Seccomp security profiles for Docker](https://docs.docker.com/engine/security/seccomp/)
- [3] [Kubernetes Docs: Restrict a Container's Syscalls with seccomp](https://kubernetes.io/docs/tutorials/security/seccomp/)

{{#include ../../../../banners/hacktricks-training.md}}
