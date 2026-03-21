# 容器安全

{{#include ../../../banners/hacktricks-training.md}}

## 容器到底是什么

一种实用的定义容器的方法是：容器是一个在特定 OCI-style 配置下启动的、能够看到受控文件系统、受控内核资源集合和受限权限模型的常规 Linux 进程树（**regular Linux process tree**）。进程可能认为自己是 PID 1，可能认为拥有自己的网络栈、自己的主机名和 IPC 资源，甚至可能在自己的 user namespace 内以 root 身份运行。但在底层它仍然是一个由内核像调度任何其他进程一样调度的主机进程。

这就是为什么容器安全其实是研究这种“幻觉”如何被构造以及如何失效的学问。如果 mount namespace 弱，进程可能会看到主机文件系统。如果 user namespace 缺失或被禁用，容器内的 root 可能与主机上的 root 映射得过于接近。如果 seccomp 未受限且 capability 集过于宽泛，进程可能调用本应无法触及的 syscalls 和特权内核功能。如果 runtime socket 被挂载到容器内，容器甚至可能不需要内核逃逸，因为它可以简单地请求 runtime 启动一个更高权限的兄弟容器或直接挂载主机根文件系统。

## 容器与虚拟机的区别

VM 通常携带自己的内核和硬件抽象边界。这意味着 guest kernel 崩溃、panic 或被利用，并不必然意味着可以直接控制 host kernel。而在容器中，工作负载并没有获得一个独立的内核。相反，它获得的是与主机使用的同一内核的经过精心过滤和命名空间化的视图。因此，容器通常更轻量、启动更快、更容易在一台机器上打包得更密集，也更适合短生命周期的应用部署。代价是隔离边界更直接依赖于主机和 runtime 的正确配置。

这并不意味着容器“没安全性”而 VM“有安全性”。它意味着安全模型不同。一个配置良好的容器堆栈（具备 rootless 执行、user namespaces、默认 seccomp、严格的 capability 集、无主机命名空间共享，以及强制的 SELinux 或 AppArmor）可以非常稳健。相反，一个使用 `--privileged` 启动、共享主机 PID/网络、将 Docker socket 挂载进去并对 `/` 进行了可写 bind mount 的容器，在功能上比安全隔离的应用沙箱更接近主机 root 访问。差异来自于哪些层被启用或禁用了。

还有一个读者应当理解的中间地带，因为它在真实环境中越来越常见。诸如 gVisor 和 Kata Containers 这样的 sandboxed container runtimes 有意在经典的 `runc` 容器之外加强边界。gVisor 在工作负载和许多主机内核接口之间放置了一个 userspace kernel 层，而 Kata 则将工作负载启动在轻量级虚拟机内。它们仍通过容器生态系统和编排工作流使用，但其安全属性不同于普通的 OCI runtimes，不应在心智上与“普通 Docker 容器”混为一谈，以为所有行为都相同。

## 容器堆栈：多个层次，而非单一层

当有人说“这个容器不安全”时，有用的后续问题是：到底是哪一层让它不安全？容器化工作负载通常是多个组件协作的结果。

在顶层，通常有一个 image build 层，比如 BuildKit、Buildah 或 Kaniko，用来创建 OCI image 和元数据。在低级 runtime 之上，可能还有一个 engine 或 manager，比如 Docker Engine、Podman、containerd、CRI-O、Incus 或 systemd-nspawn。在集群环境中，还可能有一个 orchestrator（例如 Kubernetes）通过工作负载配置决定所请求的安全姿态。最后，实际执行 namesapces、cgroups、seccomp 和 MAC 策略的是 kernel。

这种分层模型对于理解默认值很重要。一个限制可能由 Kubernetes 请求，通过 CRI 由 containerd 或 CRI-O 翻译，转换为 OCI spec 由 runtime wrapper 生成，然后才由 `runc`、`crun`、`runsc` 或其他 runtime 针对内核强制执行。当环境之间的默认行为不同，通常是因为这些层中的某一层改变了最终配置。因此，同一机制可能在 Docker 或 Podman 中表现为 CLI 标志，在 Kubernetes 中表现为 Pod 或 `securityContext` 字段，在更底层的 runtime 堆栈中表现为为工作负载生成的 OCI 配置。因此，本节中的 CLI 示例应该被视为“特定 runtime 的语法表达通用容器概念”，而不是每个工具都支持的通用标志。

## 真正的容器安全边界

在实践中，容器安全来自于重叠的控制，而不是单一完美的控制。namespaces 隔离可见性。cgroups 控制并限制资源使用。capabilities 减少看似有特权的进程实际上能做的事。seccomp 在 syscalls 到达内核之前阻断危险调用。AppArmor 和 SELinux 在常规 DAC 检查之上增加了强制访问控制。`no_new_privs`、masked procfs 路径和只读系统路径使常见的权限滥用和 proc/sys 攻链更难以实现。runtime 本身也很重要，因为它决定了如何创建挂载、socket、标签和 namespace 加入。

这就是为什么大量容器安全文档看起来重复的原因。同一逃逸链通常依赖于多个机制同时作用。例如，可写的主机 bind mount 本身就是危险的，但如果容器同时在主机上以真实 root 运行、拥有 `CAP_SYS_ADMIN`、未受 seccomp 限制并且没有被 SELinux 或 AppArmor 限制，那么情况会变得严重得多。同样，共享主机 PID 是严重的暴露，但当它与 `CAP_SYS_PTRACE`、薄弱的 procfs 保护或像 `nsenter` 这样的 namespace-entry 工具结合时，对攻击者的价值会显著提升。因此，记录该主题的正确方式不是在每一页重复同一攻击，而是解释每一层对最终边界的贡献。

## 如何阅读本节

本节从最通用的概念到最具体的内容组织。

先从 runtime 和生态概览开始：

{{#ref}}
runtimes-and-engines.md
{{#endref}}

然后查看常常决定攻击者是否甚至需要内核逃逸的控制平面和供应链表面：

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
authorization-plugins.md
{{#endref}}

{{#ref}}
image-security-and-secrets.md
{{#endref}}

{{#ref}}
assessment-and-hardening.md
{{#endref}}

接着进入保护模型：

{{#ref}}
protections/
{{#endref}}

namespace 页面单独解释内核隔离原语：

{{#ref}}
protections/namespaces/
{{#endref}}

关于 cgroups、capabilities、seccomp、AppArmor、SELinux、`no_new_privs`、masked paths 和只读系统路径的页面解释了通常叠加在 namespaces 之上的机制：

{{#ref}}
protections/cgroups.md
{{#endref}}

{{#ref}}
protections/capabilities.md
{{#endref}}

{{#ref}}
protections/seccomp.md
{{#endref}}

{{#ref}}
protections/apparmor.md
{{#endref}}

{{#ref}}
protections/selinux.md
{{#endref}}

{{#ref}}
protections/no-new-privileges.md
{{#endref}}

{{#ref}}
protections/masked-paths.md
{{#endref}}

{{#ref}}
protections/read-only-paths.md
{{#endref}}

{{#ref}}
distroless.md
{{#endref}}

{{#ref}}
privileged-containers.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## 一个良好的初步枚举思路

在评估容器化目标时，问一小组精确的技术问题通常比立刻跳到著名的 escape PoC 更有用。首先，识别 **stack**：是 Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer，还是更专业的东西。然后识别 **runtime**：`runc`、`crun`、`runsc`、`kata-runtime` 或其他兼容 OCI 的实现。之后，检查环境是 **rootful 还是 rootless**，是否启用了 **user namespaces**，是否共享了任何 **host namespaces**，还剩下哪些 **capabilities**，是否启用了 **seccomp**，是否有 **MAC policy** 在实际强制执行，是否存在 **危险的挂载或 sockets**，以及进程是否能与 container runtime API 交互。

这些答案比基础镜像名称能告诉你更多关于真实安全姿态的信息。在许多评估中，仅通过理解最终的容器配置，你就可以在未查看任何应用文件之前预测可能的 breakout 家族。

## 涵盖范围

本节涵盖以容器为导向组织的旧 Docker 相关材料：runtime 和 daemon 暴露、authorization plugins、image trust 和 build secrets、敏感的主机挂载、distroless 工作负载、privileged containers，以及通常在容器执行周围叠加的内核保护。
