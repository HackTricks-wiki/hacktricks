# Container Protections Overview

{{#include ../../../../banners/hacktricks-training.md}}

container hardening 中最重要的理念是：不存在一个单独名为 "container security" 的控制措施。人们所称的 container isolation，实际上是多个 Linux security 和 resource-management 机制协同工作的结果。如果文档只描述其中一个机制，读者往往会高估它的强度。如果文档列出所有机制，却不解释它们如何交互，读者得到的只是一个名称目录，而没有真正的模型。本节旨在避免这两种错误。

模型的核心是 **namespaces**，它们隔离 workload 能够看到的内容。它们让进程获得对 filesystem mounts、PIDs、networking、IPC objects、hostnames、user/group mappings、cgroup paths 以及部分 clocks 的私有或部分私有视图。但 namespaces 本身并不决定进程被允许执行哪些操作。这正是下一层机制发挥作用的地方。

**cgroups** 管理 resource usage。它们并非与 mount 或 PID namespaces 完全相同意义上的 isolation boundary，但在实际运行中至关重要，因为它们会限制 memory、CPU、PIDs、I/O 和 device access。它们也具有 security 相关性，因为历史上的 breakout 技术曾滥用可写的 cgroup 功能，尤其是在 cgroup v1 环境中。

**Capabilities** 将过去无所不能的 root 模型拆分为更小的 privilege units。这对 containers 至关重要，因为许多 workloads 仍然以 container 内的 UID 0 运行。因此，问题不只是“进程是否为 root”，而是“哪些 capabilities 被保留了、位于哪些 namespaces 中、受到哪些 seccomp 和 MAC 限制？”这就是为什么一个 container 中的 root process 可能受到相对严格的约束，而另一个 container 中的 root process 在实际效果上可能几乎无法与 host root 区分。

**seccomp** 过滤 syscalls，减少 workload 暴露给 kernel 的 attack surface。它通常用于阻止明显危险的调用，例如 `unshare`、`mount`、`keyctl`，或 breakout chains 中使用的其他 syscalls。即使进程拥有某项 capability，按其他条件本可执行某个操作，seccomp 仍可能在 kernel 完整处理该操作之前，阻止其 syscall path。

**AppArmor** 和 **SELinux** 在常规 filesystem 和 privilege checks 之上增加 Mandatory Access Control。这一点尤其重要，因为即使 container 拥有超出应有范围的 capabilities，它们仍然会发挥作用。workload 可能拥有尝试某项操作的理论 privilege，但如果其 label 或 profile 禁止访问相关 path、object 或 operation，它仍然无法完成该操作。

最后，还有一些受到较少关注、但在真实攻击中经常发挥作用的额外 hardening layers：`no_new_privs`、masked procfs paths、read-only system paths、read-only root filesystems，以及谨慎设置的 runtime defaults。这些机制通常会阻止 compromise 的“最后一步”，尤其是在 attacker 试图将 code execution 转化为更广泛的 privilege gain 时。

本 folder 的其余内容将更详细地解释这些机制，包括 kernel primitive 实际执行的操作、如何在本地观察它、常见 runtimes 如何使用它，以及 operators 如何在无意中削弱它。

## 后续阅读

{{#ref}}
namespaces/
{{#endref}}

{{#ref}}
cgroups.md
{{#endref}}

{{#ref}}
capabilities.md
{{#endref}}

{{#ref}}
seccomp.md
{{#endref}}

{{#ref}}
apparmor.md
{{#endref}}

{{#ref}}
selinux.md
{{#endref}}

{{#ref}}
no-new-privileges.md
{{#endref}}

{{#ref}}
masked-paths.md
{{#endref}}

{{#ref}}
read-only-paths.md
{{#endref}}

许多真实的 escapes 还取决于哪些 host content 被 mount 到 workload 中，因此在阅读核心 protections 后，继续阅读以下内容会很有帮助：

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
