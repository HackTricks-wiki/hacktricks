# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

**seccomp** 是一种机制，允许内核对进程可能调用的系统调用应用过滤器。在容器化环境中，seccomp 通常以 filter 模式使用，这样进程不会仅仅被模糊地标记为“受限”，而是受到具体的系统调用策略约束。这一点很重要，因为许多容器突破依赖于访问非常具体的内核接口。如果进程无法成功调用相关的系统调用，那么在任何 namespaces 或 capabilities 的细微差别变得相关之前，许多类型的攻击就已经无法实现。

关键的思维模型很简单：namespaces 决定 **what the process can see**，capabilities 决定 **which privileged actions the process is nominally allowed to attempt**，而 seccomp 决定 **whether the kernel will even accept the syscall entry point for the attempted action**。这就是为什么 seccomp 经常阻止那些仅凭 capabilities 看起来可行的攻击。

## 安全影响

大量危险的内核面向只能通过相对少量的系统调用访问。在容器加固中反复出现的重要示例包括 `mount`、`unshare`、带有特定标志的 `clone` 或 `clone3`、`bpf`、`ptrace`、`keyctl` 和 `perf_event_open`。能够访问这些系统调用的攻击者可能创建新的 namespaces、操纵内核子系统，或者与普通应用容器根本不需要的攻击面交互。

这就是为什么默认的运行时 seccomp 配置文件如此重要。它们不仅仅是“额外的防御”。在许多环境中，它们决定了容器是能够调用广泛内核功能，还是被限制在更接近应用实际需要的系统调用表面。

## 模式与过滤器构建

seccomp 在历史上有一种 strict 模式，在该模式下只有极少的系统调用可用，但与现代容器 runtime 相关的模式是 seccomp filter 模式，通常称为 **seccomp-bpf**。在这种模型中，内核会评估一个过滤程序，该程序决定某个系统调用是否应被允许、以 errno 拒绝、陷阱、记录日志或终止进程。容器 runtimes 使用该机制，因为它足够表达性，可以阻止大量危险的系统调用类别，同时仍允许正常的应用行为。

两个低级示例是有用的，因为它们使该机制变得具体而非神秘。Strict 模式演示了旧的“仅保留最小系统调用集”模型：
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
最后的 `open` 会导致进程被终止，因为它不属于严格模式的最小集合。

一个 libseccomp filter 示例更清楚地展示了现代策略模型：
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
这种策略风格是大多数读者在想到运行时 seccomp 配置文件时应该想象的样子。

## 实验

验证 seccomp 在容器中处于活动状态的一个简单方法是：
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
你也可以尝试一个默认配置通常会限制的操作：
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
如果容器在一个普通的默认 seccomp 配置下运行，`unshare`-类型的操作通常会被阻止。  
这是一个有用的示例，因为它表明即使 userspace 工具存在于镜像内，所需的内核路径仍可能不可用。

如果容器在一个普通的默认 seccomp 配置下运行，`unshare`-类型的操作通常会被阻止，即使 userspace 工具存在于镜像内。

要更一般地检查进程状态，请运行：
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## 运行时使用

Docker 支持默认和自定义 seccomp 配置文件，并允许管理员使用 `--security-opt seccomp=unconfined` 将其禁用。Podman 提供类似的支持，并且常常将 seccomp 与 rootless 执行配合，形成一个非常合理的默认策略。Kubernetes 通过工作负载配置暴露 seccomp，其中 `RuntimeDefault` 通常是合理的基线，而 `Unconfined` 应被视为需要理由的例外，而不是一个便捷的切换。

在基于 containerd 和 CRI-O 的环境中，具体路径更为分层，但原则相同：上层的引擎或编排器决定应发生什么，运行时最终会为容器进程安装生成的 seccomp 策略。最终结果仍取决于到达内核的最终运行时配置。

### 自定义策略示例

Docker 等类似引擎可以从 JSON 加载自定义 seccomp 配置。下面是一个最小示例，它拒绝 `chmod` 而允许其他所有操作，示例如下：
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
使用：
```bash
docker run --rm -it --security-opt seccomp=/path/to/profile.json busybox chmod 400 /etc/hosts
```
该命令返回 `Operation not permitted`，表明限制来自 syscall 策略，而不是单纯的文件权限。在实际加固中，allowlists 通常比以小型 blacklist 为默认的宽松策略更强。

## Misconfigurations

最粗暴的错误是因为应用在默认策略下失败，就把 seccomp 设置为 **unconfined**。这在排错时很常见，但作为永久修复非常危险。一旦过滤器被移除，许多基于 syscall 的越狱原语会再次可达，特别是在存在 powerful capabilities 或 host namespace sharing 时。

另一个常见问题是使用从某个博客或内部变通方案复制而来、未经仔细审查的 **custom permissive profile**。团队有时会保留几乎所有危险的 syscalls，仅仅因为该 profile 是基于“防止应用崩溃”而非“只授予应用实际需要的权限”来构建的。第三个误解是认为 seccomp 对非 root 容器不那么重要。实际上，即便进程不是 UID 0，仍有大量内核攻击面相关联。

## Abuse

如果 seccomp 缺失或被严重弱化，攻击者可能能够调用命名空间创建类的 syscalls，通过 `bpf` 或 `perf_event_open` 扩大可达的内核攻击面，滥用 `keyctl`，或将这些 syscall 路径与诸如 `CAP_SYS_ADMIN` 之类的危险 capabilities 结合。在许多真实攻击中，seccomp 不是唯一缺失的控制，但它的缺失会显著缩短利用链，因为这会移除少数可以在特权模型其他部分生效前阻止危险 syscall 的防线之一。

最有用的实测方法是尝试那些默认 profile 通常会阻止的具体 syscall 家族。如果它们突然可用，说明容器的安全态势发生了重大变化：
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
如果存在 `CAP_SYS_ADMIN` 或另一个强权限，测试 seccomp 是否是在进行基于 mount 的滥用之前唯一缺失的防护：
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
在某些目标上，眼前的价值并不是完全 escape，而是信息收集和扩展 kernel attack-surface。这些命令有助于判断是否能到达特别敏感的 syscall 路径：
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
如果没有 seccomp，并且容器在其他方面也具有特权，那么此时就有必要转向已经在遗留的 container-escape 页面中记录的更具体的 breakout 技术。

### 完整示例：seccomp 是阻止 `unshare` 的唯一因素

在许多目标上，移除 seccomp 的实际效果是命名空间创建或 mount 系统调用突然开始工作。如果容器还具有 `CAP_SYS_ADMIN`，则以下序列可能变为可行：
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
单独来看，这还不是 host escape，但它表明 seccomp 是阻止与 mount 相关利用的障碍。

### 完整示例：seccomp 禁用 + cgroup v1 `release_agent`

如果 seccomp 被禁用并且容器可以挂载 cgroup v1 层次结构，那么来自 cgroups 部分的 `release_agent` 技术就变得可达：
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
这不是一个仅依赖 seccomp 的 exploit。关键在于，一旦 seccomp 不受限制，之前被阻止的 syscall-heavy breakout chains 可能会完全按原样工作。

## Checks

这些检查的目的是确定 seccomp 是否根本处于启用状态、`no_new_privs` 是否伴随启用，以及运行时配置是否明确显示 seccomp 被禁用。
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
这里值得关注的点：

- 非零的 `Seccomp` 值表示过滤已启用；`0` 通常表示没有 seccomp 保护。
- 如果 runtime 的安全选项包含 `seccomp=unconfined`，则工作负载失去了其中一种最有用的 syscall 级防御。
- `NoNewPrivs` 本身不是 seccomp，但两者同时存在通常比两者都不存在时更能表明更谨慎的加固姿态。

如果容器已经有可疑的挂载、广泛的 capabilities，或与宿主共享的 namespaces，并且 seccomp 也被设为 unconfined，那么这种组合应被视为重大权限升级信号。容器可能仍然不容易被轻易攻破，但攻击者可利用的内核入口点数量已急剧增加。

## 运行时默认值

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动放宽方式 |
| --- | --- | --- | --- |
| Docker Engine | 通常默认启用 | 使用 Docker 内置的默认 seccomp profile，除非被覆盖 | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | 通常默认启用 | 应用运行时默认的 seccomp profile，除非被覆盖 | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **默认不保证** | 如果 `securityContext.seccompProfile` 未设置，默认值为 `Unconfined`，除非 kubelet 启用了 `--seccomp-default`；否则必须显式设置为 `RuntimeDefault` 或 `Localhost` | `securityContext.seccompProfile.type: Unconfined`, 在未启用 `seccompDefault` 的集群上未设置 seccomp, `privileged: true` |
| containerd / CRI-O under Kubernetes | 遵循 Kubernetes 节点和 Pod 的设置 | 当 Kubernetes 请求 `RuntimeDefault` 或 kubelet 启用 seccomp 默认值时，使用 runtime profile | 与 Kubernetes 行相同；直接的 CRI/OCI 配置也可以完全省略 seccomp |

Kubernetes 的行为是最常让运维人员感到意外的。在许多集群中，seccomp 仍然不存在，除非 Pod 请求它或 kubelet 配置为默认使用 `RuntimeDefault`。
