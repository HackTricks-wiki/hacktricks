# seccomp

{{#include ../../../../banners/hacktricks-training.md}}

## 概述

**seccomp** 是让内核对进程可能调用的 syscalls 应用过滤器的机制。在容器化环境中，seccomp 通常以 filter 模式使用，这样进程不会被模糊地标记为 "restricted"，而是受具体的 syscall 策略约束。这一点很重要，因为许多容器逃逸需要访问非常特定的内核接口。如果进程无法成功调用相关的 syscalls，在任何 namespaces 或 capabilities 的细微差别变得相关之前，大量攻击就已经消失了。

关键的思维模型很简单：namespaces 决定 **what the process can see**，capabilities 决定 **which privileged actions the process is nominally allowed to attempt**，而 seccomp 决定 **whether the kernel will even accept the syscall entry point for the attempted action**。这就是为什么 seccomp 经常能阻止那些仅凭 capabilities 看起来可行的攻击。

## 安全影响

许多危险的内核攻击面只有通过相对少数的 syscalls 才能到达。在容器加固中反复重要的示例包括 `mount`、`unshare`、带特定标志的 `clone` 或 `clone3`、`bpf`、`ptrace`、`keyctl` 和 `perf_event_open`。能够访问这些 syscalls 的攻击者可能创建新的 namespaces、操纵内核子系统，或与普通应用容器根本不需要的攻击面交互。

这就是默认 runtime seccomp 配置文件如此重要的原因。它们不仅仅是“额外的防御”。在许多环境中，它们决定了容器是能够调用广泛内核功能的容器，还是被约束到更接近应用真实需求的 syscall 面的容器。

## 模式与过滤器构建

seccomp 在历史上有一种 strict 模式，在该模式下只有极少数的 syscall 可用，但对现代容器 runtime 相关的模式是 seccomp filter 模式，通常称为 **seccomp-bpf**。在这种模型中，内核评估一个过滤器程序来决定某个 syscall 是否应被允许、以 errno 拒绝、被 trap、被记录，或导致进程被杀死。容器 runtime 使用该机制，因为它的表达力足以阻止危险 syscall 的广泛类别，同时仍允许正常的应用行为。

两个底层示例很有用，因为它们把机制具体化而不是神秘化。Strict 模式展示了旧的“只有最小 syscall 集存活”模型：
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
最后那个 `open` 会导致进程被杀死，因为它不在 strict 模式的最小集合中。

一个 libseccomp 过滤器示例更清晰地展示了现代策略模型：
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
当读者想到运行时 seccomp 配置文件时，大多数人应当想象的就是这种策略风格。

## 实验

确认 seccomp 在 container 中处于启用状态的一种简单方法是：
```bash
docker run --rm debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
docker run --rm --security-opt seccomp=unconfined debian:stable-slim sh -c 'grep Seccomp /proc/self/status'
```
你也可以尝试默认配置通常会限制的操作：
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y util-linux >/dev/null 2>&1 && unshare -Ur true'
```
如果容器在默认的 seccomp 配置下运行，`unshare`-风格的操作通常会被阻止。这是一个有用的示例，因为它表明即使用户空间工具存在于镜像中，所需的内核路径仍可能不可用。
如果容器在默认的 seccomp 配置下运行，`unshare`-风格的操作通常会被阻止，即使用户空间工具存在于镜像中。

要更一般性地检查进程状态，请运行：
```bash
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
```
## 运行时使用

Docker 支持默认和自定义 seccomp 配置文件，并允许管理员使用 `--security-opt seccomp=unconfined` 将其禁用。Podman 也有类似支持，并且通常将 seccomp 与 rootless execution 配对，作为一个合理的默认姿态。Kubernetes 通过工作负载配置暴露 seccomp，其中 `RuntimeDefault` 通常是合理的基线，而 `Unconfined` 应被视为需要理由的例外，而非便捷的开关。

在基于 containerd 和 CRI-O 的环境中，确切的路径更为分层，但原理相同：上层引擎或编排器决定应当发生什么，运行时最终为容器进程安装生成的 seccomp 策略。结果仍取决于到达内核的最终运行时配置。

### 自定义策略示例

Docker 和类似引擎可以从 JSON 加载自定义 seccomp 配置文件。一个最小示例，拒绝 `chmod` 而允许其他所有操作，示例如下：
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
该命令返回 `Operation not permitted`，说明限制来自 syscall 策略，而非普通文件权限。在实际加固中，allowlists 通常比默认宽松并配少量 blacklist 的策略更强。

## Misconfigurations

最粗暴的错误是因为应用在默认策略下失败就把 seccomp 设置为 **unconfined**。这在排查故障时很常见，但作为永久修复非常危险。一旦过滤器被移除，许多基于 syscall 的突破原语会再次可达，尤其是在存在 powerful capabilities 或 host namespace sharing 时。

另一个常见问题是使用 **custom permissive profile**，通常是从某篇博客或内部权宜方案复制过来却没有经过仔细审查。团队有时会保留几乎所有危险的 syscalls，仅仅因为该 profile 的目标是“让应用不崩溃”，而不是“只授予应用实际需要的权限”。第三个误解是认为 seccomp 对非 root 容器不那么重要。实际上，即便进程不是 UID 0，仍有大量内核攻击面是相关的。

## Abuse

如果 seccomp 缺失或被严重弱化，攻击者可能能够调用 namespace-creation syscalls，通过 `bpf` 或 `perf_event_open` 扩展可达的内核攻击面，滥用 `keyctl`，或将这些 syscall 路径与危险的 capabilities（例如 `CAP_SYS_ADMIN`）结合。在许多真实攻击中，seccomp 并不是唯一缺失的控制，但它的缺失会显著缩短利用链路，因为它移除了为数不多的、能在特权模型其他部分介入前阻止危险 syscall 的防线之一。

最有用的实测是尝试那些默认 profiles 通常会阻止的确切 syscall 家族。如果它们突然可用，说明容器的 posture 已经发生很大变化：
```bash
grep Seccomp /proc/self/status
unshare -Ur true 2>/dev/null && echo "unshare works"
unshare -m true 2>/dev/null && echo "mount namespace creation works"
```
如果存在 `CAP_SYS_ADMIN` 或其他强权限，请测试 seccomp 是否是在进行基于 mount 的滥用之前唯一缺失的屏障：
```bash
capsh --print | grep cap_sys_admin
mkdir -p /tmp/m
mount -t tmpfs tmpfs /tmp/m 2>/dev/null && echo "tmpfs mount works"
mount -t proc proc /tmp/m 2>/dev/null && echo "proc mount works"
```
在某些目标上，直接的价值并不是完全 escape，而是 information gathering 和 kernel attack-surface expansion。以下命令有助于判断尤其敏感的 syscall 路径是否可达：
```bash
which unshare nsenter strace 2>/dev/null
strace -e bpf,perf_event_open,keyctl true 2>&1 | tail
```
如果 seccomp 不存在且容器在其他方面也具有特权，那么这时转向遗留 container-escape 页面中已经记录的更具体 breakout 技术才有意义。

### 完整示例：seccomp 是阻止 `unshare` 的唯一因素

在许多目标上，移除 seccomp 的实际效果是命名空间创建或 mount 系统调用突然开始工作。如果容器还有 `CAP_SYS_ADMIN`，则以下序列可能变为可行：
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
单凭这一点还不能导致 host escape，但它证明了 seccomp 是阻止与 mount 相关利用的屏障。

### 完整示例：seccomp 已禁用 + cgroup v1 `release_agent`

如果 seccomp 被禁用且容器能够挂载 cgroup v1 层次结构，则来自 cgroups 部分的 `release_agent` 技术将变得可达：
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
这不是一个仅针对 seccomp 的 exploit。关键是，一旦 seccomp 被解除限制，之前被阻止的 syscall-heavy breakout chains 可能会按原样开始工作。

## 检查

这些检查的目的是确定 seccomp 是否启用，`no_new_privs` 是否伴随启用，以及运行时配置是否明确显示 seccomp 被禁用。
```bash
grep Seccomp /proc/self/status                               # Current seccomp mode from the kernel
cat /proc/self/status | grep NoNewPrivs                      # Whether exec-time privilege gain is also blocked
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt'   # Runtime security options, including seccomp overrides
```
这里值得注意的点：

- 非零 `Seccomp` 值表示已启用过滤；`0` 通常表示没有 seccomp 保护。
- 如果运行时安全选项包含 `seccomp=unconfined`，则该工作负载已失去最有用的系统调用级别防护之一。
- NoNewPrivs 不是 seccomp 本身，但同时看到两者通常表示比两者都未看到时更为谨慎的加固姿态。

如果容器已经存在可疑的挂载、宽泛的 capabilities，或与宿主共享的命名空间，并且 seccomp 也处于 unconfined 状态，则应将该组合视为重大权限升级信号。该容器可能仍然不易被直接攻破，但攻击者可利用的内核入口点数量已急剧增加。

## 运行时默认值

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Usually enabled by default | Uses Docker's built-in default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=/path/profile.json`, `--privileged` |
| Podman | Usually enabled by default | Applies the runtime default seccomp profile unless overridden | `--security-opt seccomp=unconfined`, `--security-opt seccomp=profile.json`, `--seccomp-policy=image`, `--privileged` |
| Kubernetes | **默认不保证** | If `securityContext.seccompProfile` is unset, the default is `Unconfined` unless the kubelet enables `--seccomp-default`; `RuntimeDefault` or `Localhost` must otherwise be set explicitly | `securityContext.seccompProfile.type: Unconfined`, leaving seccomp unset on clusters without `seccompDefault`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes node and Pod settings | Runtime profile is used when Kubernetes asks for `RuntimeDefault` or when kubelet seccomp defaulting is enabled | Same as Kubernetes row; direct CRI/OCI configuration can also omit seccomp entirely |

Kubernetes 的行为最常让运维人员感到惊讶。在许多集群中，seccomp 仍然缺失，除非 Pod 请求它或 kubelet 被配置为默认使用 `RuntimeDefault`。
{{#include ../../../../banners/hacktricks-training.md}}
