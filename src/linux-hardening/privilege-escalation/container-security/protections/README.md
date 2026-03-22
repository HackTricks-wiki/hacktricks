# 容器防护概览

{{#include ../../../../banners/hacktricks-training.md}}

容器加固的最重要观点是：没有一个单独的控制项可以被称为“container security”。人们所谓的容器隔离实际上是多个 Linux 安全和资源管理机制协同工作的结果。如果文档只描述其中一个，读者往往会高估它的强度；如果文档列出所有机制但不解释它们如何相互作用，读者则只能得到一份名词目录而无真实模型。本节试图避免这两种错误。

模型的中心是 **namespaces**，它们隔离了工作负载能看到的内容。namespaces 给进程提供了私有或部分私有的视图，包括文件系统挂载、PIDs、网络、IPC 对象、主机名、用户/组映射、cgroup 路径和一些时钟。但仅靠 namespaces 并不能决定一个进程被允许做什么。接下来几层才起决定作用。

**cgroups** 管理资源使用。它们并不像 mount 或 PID namespaces 那样主要作为隔离边界，但在实际运维中至关重要，因为它们约束内存、CPU、PID、I/O 和设备访问。它们也具有安全相关性，因为历史上的越狱技术滥用了可写 cgroup 特性，尤其是在 cgroup v1 环境中。

**Capabilities** 把旧的全能 root 模型拆分为更小的特权单元。这对容器非常重要，因为许多工作负载在容器内仍以 UID 0 运行。因此问题不再只是“进程是否为 root？”，而是“哪些 capabilities 在哪些 namespaces 内存活，以及它们受到哪些 seccomp 和 MAC 限制？”这就是为什么一个容器中的 root 进程可能被相对限制，而另一个容器中的 root 进程在实践中几乎无法与主机 root 区分开来。

**seccomp** 过滤 syscall 并减少内核向工作负载暴露的攻击面。这通常是阻止明显危险调用（例如 `unshare`、`mount`、`keyctl` 或在越狱链中使用的其他 syscalls）的机制。即使进程拥有本可允许某操作的 capability，seccomp 仍可能在内核完全处理前阻止该 syscall 路径。

**AppArmor** 和 **SELinux** 在普通文件系统和特权检查之上加入强制访问控制（MAC）。这些尤其重要，因为即便容器获得了比应有更多的 capabilities，它们仍然会发挥作用。工作负载可能理论上有权尝试某项操作，但仍会因为其 label 或 profile 禁止访问相关路径、对象或操作而无法执行。

最后，还有一些较少被关注但在真实攻击中经常起作用的加固层：`no_new_privs`、被屏蔽的 procfs 路径、只读系统路径、只读根文件系统，以及谨慎的运行时默认设置。这些机制通常阻止妥协的“最后一英里”，尤其是当攻击者尝试将代码执行转化为更广泛的特权提升时。

本文件夹其余部分更详细地解释了每种机制，包括内核原语的实际功能、如何在本地观察、常见 runtime 的使用方式，以及运维人员如何意外削弱它们。

## 接着阅读

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

许多真实的逃逸还依赖于主机内容被如何挂载到工作负载中，所以在阅读完核心防护后，继续阅读以下内容会很有帮助：

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
{{#include ../../../../banners/hacktricks-training.md}}
