# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

**seccomp** 是一种机制，允许内核对进程可以调用的 syscalls 应用过滤器。在容器化环境中，seccomp 通常以 filter mode 使用，使进程并非只是以模糊的方式被标记为“restricted”，而是受到具体 syscall policy 的约束。这一点很重要，因为许多 container breakout 都需要访问非常特定的内核接口。如果进程无法成功调用相关 syscalls，那么大量攻击会在 namespace 或 capability 的细节变得相关之前就被阻止。

关键的理解模型很简单：namespaces 决定**进程可以看到什么**，capabilities 决定**进程名义上被允许尝试哪些特权操作**，而 seccomp 决定**对于所尝试的操作，内核是否甚至会接受其 syscall entry point**。这就是为什么 seccomp 经常能够阻止那些仅根据 capabilities 看起来似乎可行的攻击。

## 安全影响

许多危险的内核攻击面只能通过相对较少的一组 syscalls 访问。在 container hardening 中反复需要关注的例子包括 `mount`、`unshare`、带有特定 flags 的 `clone` 或 `clone3`、`bpf`、`ptrace`、`keyctl` 以及 `perf_event_open`。能够访问这些 syscalls 的攻击者，可能创建新的 namespaces、操纵内核子系统，或与普通 application container 完全不需要的攻击面进行交互。

这就是默认 runtime seccomp profiles 如此重要的原因。它们并不只是“额外的防御”。在许多环境中，它们决定了一个 container 是能够使用广泛的内核功能，还是被限制在更接近应用实际需求的 syscall surface 中。

## 模式与 Filter 构建

seccomp 历史上提供过 strict mode，在该模式下只有极少量的 syscall set 仍然可用；但现代 container runtimes 相关的模式是 seccomp filter mode，通常称为 **seccomp-bpf**。在此模型中，内核会执行一个 filter program，由它决定某个 syscall 应被允许、以 errno 拒绝、trapped、记录日志，还是终止进程。Container runtimes 使用这一机制，是因为它足够灵活，能够阻止大类危险 syscalls，同时继续允许正常的 application behavior。

下面的两个 low-level 示例很有用，因为它们能让这一机制变得具体，而不是显得神秘。Strict mode 展示了旧式的“只有最小 syscall set 能够保留”的模型：
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
最后的 `open` 会导致进程被终止，因为它不属于 strict mode 的最小集合。

下面的 libseccomp filter 示例更清晰地展示了现代 policy 模型：
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
大多数读者想到 runtime seccomp profiles 时，应该设想的就是这种策略。

## 实验

确认容器中 seccomp 已启用的一种简单方法是：
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
你还可以尝试执行一项默认 profiles 通常会限制的操作：
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
如果容器运行在正常的默认 seccomp profile 下，`unshare`-style 操作通常会被阻止。这是一个很有用的演示，因为它表明，即使 userspace 工具存在于 image 中，它所需的 kernel 路径仍可能不可用。

如果容器运行在正常的默认 seccomp profile 下，即使 userspace 工具存在于 image 中，`unshare`-style 操作也通常会被阻止。

要更全面地检查进程状态，请运行：
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## Runtime 用法

Docker 支持默认和自定义的 seccomp profiles，并允许管理员通过 `--security-opt seccomp=unconfined` 将其禁用。Podman 也提供类似支持，并且通常会将 seccomp 与 rootless execution 结合使用，这是一种非常合理的默认安全配置。Kubernetes 通过 workload configuration 提供 seccomp，`RuntimeDefault` 通常是合理的基线，而 `Unconfined` 应被视为需要说明理由的例外，而不是方便的切换选项。

在基于 containerd 和 CRI-O 的环境中，具体路径会更加分层，但原则相同：更高层的 engine 或 orchestrator 决定应采取的措施，runtime 最终会为 container process 安装生成的 seccomp policy。最终结果仍取决于传递到 kernel 的最终 runtime configuration。

### Custom Policy 示例

Docker 和类似的 engine 可以从 JSON 加载自定义 seccomp profile。下面是一个在允许其他所有操作的同时拒绝 `chmod` 的最小示例：
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
该命令失败并返回 `Operation not permitted`，说明限制来自 syscall policy，而不仅仅是普通文件权限。在实际 hardening 中，allowlist 通常比带有少量 blacklist 的宽松默认设置更强。

## Misconfigurations

最粗暴的错误，是因为应用在默认 policy 下运行失败，就将 seccomp 设置为 **unconfined**。这在故障排查期间很常见，但作为永久修复极其危险。filter 一旦被移除，许多基于 syscall 的 breakout primitives 会再次变得可用，尤其是在同时存在强大 capabilities 或共享 host namespace 的情况下。

另一个常见问题，是使用未经仔细审查、从某篇 blog 或内部 workaround 复制而来的 **custom permissive profile**。团队有时会保留几乎所有危险 syscall，仅仅因为该 profile 的设计目标是“阻止应用出错”，而不是“只授予应用实际需要的权限”。第三个误区，是认为 seccomp 对 non-root containers 不那么重要。实际上，即使进程不是 UID 0，仍有大量 kernel attack surface 可能被利用。

## Abuse

如果 seccomp 缺失或被严重削弱，攻击者可能能够调用 namespace-creation syscalls，通过 `bpf` 或 `perf_event_open` 扩大可触达的 kernel attack surface，滥用 `keyctl`，或将这些 syscall 路径与 `CAP_SYS_ADMIN` 等危险 capabilities 结合起来。在许多真实攻击中，seccomp 并不是唯一缺失的控制措施，但它的缺失会大幅缩短 exploit path，因为这移除了少数能够在 privilege model 的其他部分介入之前阻止高风险 syscall 的防御措施之一。

最实用的测试方法，是尝试 default profiles 通常会阻止的确切 syscall families。如果它们突然可以正常工作，说明 container posture 已发生很大变化：
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
如果存在 `CAP_SYS_ADMIN` 或其他强大的 capability，请测试 seccomp 是否是阻止基于 mount 的滥用的唯一屏障：
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
在某些目标上，直接价值并不是完全逃逸，而是信息收集和扩大 kernel attack surface。这些命令有助于确定是否能够访问尤其敏感的 syscall 路径：
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
如果 seccomp 缺失，并且容器还具有其他特权，那么此时转向 legacy container-escape 页面中已经记录的更具体 breakout techniques 才有意义。

### 完整示例：seccomp 是唯一阻止 `unshare` 的因素

在许多目标上，移除 seccomp 的实际效果是：创建 namespace 或执行 mount 的系统调用突然开始正常工作。如果容器还具有 `CAP_SYS_ADMIN`，则可能可以执行以下步骤：
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
仅凭这一点还不能实现 host escape，但它说明 seccomp 正是阻止 mount 相关 exploitation 的屏障。

### 完整示例：seccomp 已禁用 + cgroup v1 `release_agent`

如果 seccomp 已禁用，且 container 可以挂载 cgroup v1 hierarchies，那么 cgroups section 中的 `release_agent` technique 就可以使用：
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
这不是一个仅依赖 seccomp 的 exploit。重点在于，一旦 seccomp 处于 unconfined 状态，之前被阻止的、严重依赖 syscall 的 breakout chain 可能会按原样开始生效。

## 检查

这些检查旨在确认 seccomp 是否处于 active 状态、是否同时启用了 `no_new_privs`，以及 runtime configuration 是否明确显示 seccomp 已被禁用。
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
这里有哪些值得关注的点：

- 非零的 `Seccomp` 值表示过滤处于启用状态；`0` 通常表示没有 seccomp protection。
- 如果 runtime security options 包含 `seccomp=unconfined`，则 workload 已失去其最有用的 syscall-level defenses 之一。
- `NoNewPrivs` 本身不是 seccomp，但同时看到这两项，通常表示其 hardening posture 比两者都不存在时更加谨慎。

如果一个 container 已经存在可疑 mounts、宽泛的 capabilities 或共享的 host namespaces，同时 seccomp 也是 unconfined，那么这种组合应被视为重要的 escalation signal。container 可能仍然无法被轻易突破，但 attacker 可用的 kernel entry points 数量已经大幅增加。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 通常默认启用 | 使用 Docker 内置的 default seccomp profile，除非被覆盖 | `--security-opt seccomp=unconfined`、`--security-opt seccomp=/path/profile.json`、`--privileged` |
| Podman | 通常默认启用 | 使用 runtime default seccomp profile，除非被覆盖 | `--security-opt seccomp=unconfined`、`--security-opt seccomp=profile.json`、`--seccomp-policy=image`、`--privileged` |
| Kubernetes | **默认情况下不保证启用** | 如果未设置 `securityContext.seccompProfile`，则 default 为 `Unconfined`，除非 kubelet 启用了 `--seccomp-default`；否则必须显式设置 `RuntimeDefault` 或 `Localhost` | `securityContext.seccompProfile.type: Unconfined`、在未启用 `seccompDefault` 的 clusters 中不设置 seccomp、`privileged: true` |
| containerd / CRI-O under Kubernetes | 遵循 Kubernetes node 和 Pod 设置 | 当 Kubernetes 请求 `RuntimeDefault`，或 kubelet 启用了 seccomp defaulting 时，使用 runtime profile | 与 Kubernetes 行相同；直接的 CRI/OCI configuration 也可能完全省略 seccomp |

Kubernetes 的行为最容易让 operators 感到意外。在许多 clusters 中，除非 Pod 请求 seccomp，或 kubelet 被配置为默认使用 `RuntimeDefault`，否则 seccomp 仍然处于缺失状态。
{{#include ../../../../banners/hacktricks-training.md}}
