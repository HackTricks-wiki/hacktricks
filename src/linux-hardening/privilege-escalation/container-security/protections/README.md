# 容器防护概览

{{#include ../../../../banners/hacktricks-training.md}}

容器加固最重要的观念是不存在一个叫做“container security”的单一控制。人们所说的容器隔离其实是多个 Linux 安全与资源管理机制协同工作的结果。如果文档只描述其中一个机制，读者往往会高估它的强度；如果文档把所有机制都列出但不解释它们如何相互作用，读者得到的只是一长串名称而没有实际模型。本节试图避免这两种错误。

模型的中心是 **namespaces**，它们隔离了工作负载可以看到的内容。namespaces 为进程提供私有或部分私有的视图，包括 filesystem mounts、PIDs、networking、IPC objects、hostnames、user/group mappings、cgroup paths 以及某些时钟。但单靠 namespaces 并不能决定进程被允许做什么。接下来的层级在这里发挥作用。

**cgroups** 管理资源使用。它们并不主要作为像 mount 或 PID namespaces 那样的隔离边界，但在实际运行中至关重要，因为它们限制了内存、CPU、PIDs、I/O 和设备访问。它们也具有安全相关性，因为历史上的逃逸技巧滥用了可写的 cgroup 特性，尤其是在 cgroup v1 环境中。

**Capabilities** 把过去无所不能的 root 模型拆分成更小的权限单元。对于容器来说这很关键，因为许多工作负载仍在容器内以 UID 0 运行。因此问题不再单纯是“进程是不是 root？”，而是“在那些 namespaces、在什么 seccomp 和 MAC 限制下，哪些 capabilities 被保留了？”这就是为什么一个容器中的 root 进程可能受到较多约束，而另一个容器中的 root 进程在实际中几乎无法与主机 root 区分开来。

**seccomp** 过滤 syscalls，减少内核向工作负载暴露的攻击面。这通常是阻止明显危险调用（例如 `unshare`、`mount`、`keyctl` 或其他在逃逸链中使用的 syscall）的机制。即便一个进程拥有本应允许某操作的 capability，seccomp 仍可能在内核完全处理之前拦截该 syscall 路径。

**AppArmor** 和 **SELinux** 在普通文件系统与权限检查之上增加了强制访问控制（Mandatory Access Control）。它们尤为重要，因为即便容器具有比应有更多的 capabilities，这些 MAC 机制仍可能发挥作用。工作负载或许理论上拥有尝试某个操作的权限，但仍可能因为其标签或 profile 禁止访问相关路径、对象或操作而无法实施。

最后，还有一些不那么受关注但在真实攻击中经常起作用的加固层：`no_new_privs`、被 mask 的 procfs 路径、只读的系统路径、只读根文件系统和谨慎的运行时默认设置。这些机制常常阻止妥协的“最后一公里”，尤其当攻击者试图把代码执行转化为更广泛的权限提升时。

本文件夹其余部分更详细地解释了每种机制，包括内核原语的实际作用、如何在本地观察、常见 runtime 如何使用它们，以及操作者如何无意中削弱这些机制。

## 继续阅读

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

许多真实的逃逸还依赖于主机内容被挂载到工作负载中的情况，因此在阅读完核心防护后，继续阅读下列内容会很有用：

{{#ref}}
../sensitive-host-mounts.md
{{#endref}}
