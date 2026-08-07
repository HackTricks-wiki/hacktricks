# Container 防护概览

{{#include ../../../../banners/hacktricks-training.md}}

Container hardening 中最重要的理念是：不存在一个名为“container security”的单一控制措施。人们所称的 container isolation，实际上是多个 Linux security 和 resource-management 机制共同作用的结果。如果文档只描述其中一种机制，读者往往会高估它的强度。如果文档列出所有机制，却不解释它们如何交互，读者得到的只是一份名称目录，而不是实际的模型。本节试图避免这两种错误。

模型的核心是 **namespaces**，它们隔离 workload 能够看到的内容。它们为进程提供 filesystem mounts、PIDs、networking、IPC objects、hostnames、user/group mappings、cgroup paths 以及部分 clocks 的私有或部分私有视图。但 namespaces 本身并不决定进程被允许执行哪些操作，这正是下一层机制发挥作用的地方。

**cgroups** 管理资源使用。它们并不完全等同于 mount 或 PID namespaces 那样的 isolation boundary，但在实际运维中至关重要，因为它们会限制 memory、CPU、PIDs、I/O 以及 device access。它们也具有 security relevance，因为历史上的 breakout techniques 曾滥用可写的 cgroup features，尤其是在 cgroup v1 environments 中。

**Capabilities** 将旧式的全能 root 模型拆分成更小的 privilege units。这对于 containers 至关重要，因为许多 workloads 仍然在 container 内以 UID 0 运行。因此，问题不只是“进程是不是 root”，而是“哪些 capabilities 被保留下来、位于哪些 namespaces 中、受到哪些 seccomp 和 MAC restrictions 的约束？”这就是为什么一个 container 中的 root process 可能受到相对严格的限制，而另一个 container 中的 root process 在实践中几乎无法与 host root 区分。

**seccomp** 过滤 syscalls，从而减少 workload 暴露的 kernel attack surface。它通常用于阻止明显危险的 calls，例如 `unshare`、`mount`、`keyctl`，或 breakout chains 中使用的其他 syscalls。即使进程拥有某项 capability，理论上可以执行某个操作，seccomp 仍可能在 kernel 完整处理该 syscall path 之前将其阻止。

**AppArmor** 和 **SELinux** 在正常的 filesystem 和 privilege checks 之上增加 Mandatory Access Control。这一点尤其重要，因为即使 container 拥有超出应有范围的 capabilities，它们仍然会发挥作用。一个 workload 可能拥有尝试某项操作所需的理论 privilege，但由于其 label 或 profile 禁止访问相关 path、object 或 operation，仍然无法完成该操作。

最后，还有一些较少受到关注、但在真实 attacks 中经常发挥作用的 additional hardening layers：`no_new_privs`、masked procfs paths、read-only system paths、read-only root filesystems，以及经过谨慎设置的 runtime defaults。这些机制通常会阻止 compromise 的“最后一公里”，尤其是在 attacker 试图将 code execution 转化为更广泛的 privilege gain 时。

本 folder 的其余内容将更详细地解释这些机制，包括 kernel primitive 实际执行的操作、如何在本地观察它、常见 runtimes 如何使用它，以及 operators 如何在不经意间削弱它。

## 接下来阅读

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

许多真实的 escapes 还取决于哪些 host content 被 mount 到 workload 中，因此在阅读完核心 protections 后，继续阅读以下内容会很有帮助：

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}

{{#include ../../../../banners/hacktricks-training.md}}
