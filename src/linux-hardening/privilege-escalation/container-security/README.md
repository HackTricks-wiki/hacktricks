# 容器安全

{{#include ../../../banners/hacktricks-training.md}}

## What A Container Actually Is

一种实用的定义是：container 是一个在特定 OCI-style 配置下启动的、被限制了文件系统、内核资源集合和权限模型的常规 Linux 进程树。该进程可能认为自己是 PID 1、认为自己有独立的网络栈、认为拥有自己的 hostname 和 IPC 资源，甚至可能在自己的 user namespace 内以 root 身份运行。但从底层看，它仍然是内核像调度任何其它进程一样调度的宿主进程。

这就是为什么 container security 实际上是研究那个幻象如何被构建以及如何破裂的原因。如果 mount namespace 很弱，进程可能能看到宿主文件系统。如果 user namespace 缺失或被禁用，container 内的 root 可能与宿主上的 root 映射得太接近。如果 seccomp 未受限且 capability 集过于宽泛，进程可能触及本应无法访问的 syscalls 和特权内核功能。如果 runtime socket 被挂载到 container 内，container 甚至可能根本不需要内核越狱，因为它可以直接请求 runtime 启动一个更有权限的兄弟 container 或直接挂载宿主根文件系统。

## How Containers Differ From Virtual Machines

VM 通常携带它自己的内核和硬件抽象边界。这意味着 guest kernel 可能崩溃、panic 或被利用，而并不自动意味着对宿主内核的直接控制。在 containers 中，workload 并不会得到单独的内核。相反，它得到的是宿主使用的同一内核的经过谨慎过滤和命名空间化的视图。因此，containers 通常更轻量、启动更快、更容易在一台机器上密集打包，并且更适合短生命周期的应用部署。代价是隔离边界在很大程度上更直接依赖于宿主和 runtime 的正确配置。

这并不意味着 containers 是“不安全”的而 VM 是“安全”的。这意味着安全模型不同。一个配置良好的 container stack，具备 rootless 执行、user namespaces、默认 seccomp、严格的 capability 集、不共享宿主命名空间以及强的 SELinux 或 AppArmor 强制，可以非常稳健。相反，一个以 `--privileged` 启动、共享宿主 PID/网络、在内部挂载 Docker socket，并且对 `/` 有可写 bind mount 的 container，功能上更接近宿主 root 访问，而不是安全隔离的应用沙箱。差异来自于启用了哪些层、禁用了哪些层。

还有一种读者应当理解的中间态，因为它在真实环境中越来越常见。像 gVisor 和 Kata Containers 这样的 sandboxed container runtimes 有意将边界加固得超过经典的 `runc` container。gVisor 在 workload 与许多宿主内核接口之间放置了一个 userspace kernel 层，而 Kata 则将 workload 启动在轻量虚拟机内。它们仍然通过 container 生态和编排工作流使用，但它们的安全属性与普通 OCI runtimes 不同，不应被心理上与“普通 Docker containers”一并看待，仿佛一切行为都相同。

## The Container Stack: Several Layers, Not One

当有人说“这个 container 不安全”时，有用的后续问题是：到底是哪一层让它变得不安全？containerized workload 通常是几个组件协同工作的结果。

在顶层，通常有一个 image build 层，如 BuildKit、Buildah 或 Kaniko，用于创建 OCI image 和元数据。在低级 runtime 之上，可能有一个 engine 或 manager，例如 Docker Engine、Podman、containerd、CRI-O、Incus，或 systemd-nspawn。在集群环境中，也可能有一个 orchestrator（如 Kubernetes）通过 workload 配置决定请求的安全姿态。最后，kernel 才是真正执行 namespaces、cgroups、seccomp 和 MAC policy 的实体。

这个分层模型对于理解默认值很重要。一个限制可能由 Kubernetes 请求，通过 CRI 由 containerd 或 CRI-O 翻译，被 runtime wrapper 转换为 OCI spec，只有在 `runc`、`crun`、`runsc` 或另一个 runtime 针对内核执行时才生效。当不同环境之间的默认值不同时，通常是因为这些层中的某一层改变了最终配置。同一机制因此可能在 Docker 或 Podman 中作为 CLI 标志出现，在 Kubernetes 中作为 Pod 或 `securityContext` 字段出现，在更低级的 runtime 堆栈中则表现为为 workload 生成的 OCI 配置。因此，本节中的 CLI 示例应被视为“针对一般 container 概念的 runtime-specific 语法”，而不是所有工具都支持的通用标志。

## The Real Container Security Boundary

在实践中，container security 来自于重叠的控制，而不是单一的完美控制。Namespaces 隔离可见性。cgroups 管理并限制资源使用。Capabilities 降低了表面看起来有特权的进程实际能做的事情。seccomp 在 syscall 到达内核之前阻断危险的调用。AppArmor 和 SELinux 在正常的 DAC 检查之上增加了 Mandatory Access Control。`no_new_privs`、被屏蔽的 procfs 路径和只读的系统路径使常见的权限滥用和 proc/sys 滥用链更难实现。runtime 本身也很重要，因为它决定了 mounts、sockets、labels 和 namespace joins 如何被创建。

这就是为什么很多 container security 文档看起来重复。相同的逃逸链通常依赖于多个机制同时发挥作用。例如，一个可写的宿主 bind mount 是危险的，但如果 container 也以宿主真实 root 运行、拥有 `CAP_SYS_ADMIN`、未受 seccomp 限制、且没有被 SELinux 或 AppArmor 限制，那么情况会更糟。同样，共享宿主 PID 是一个严重暴露，但当它与 `CAP_SYS_PTRACE`、薄弱的 procfs 保护或像 `nsenter` 这样的 namespace-entry 工具结合时，它对攻击者的用处会大大增加。因此，记录该主题的正确方式不是在每一页重复相同的攻击，而是解释每一层对最终边界的贡献。

## How To Read This Section

本节从最一般的概念组织到最具体的内容。

先从 runtime 和生态概览开始：

{{#ref}}
runtimes-and-engines.md
{{#endref}}

然后查看常常决定攻击者是否甚至需要内核逃逸的 control planes 和 supply-chain 表面：

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

namespace 页面单独解释了内核隔离原语：

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

## A Good First Enumeration Mindset

在评估 containerized 目标时，提出一小组精确的技术性问题比立即跳到著名的 escape PoC 更有用。首先，识别 **stack**：Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer，或更专用的东西。然后识别 **runtime**：`runc`、`crun`、`runsc`、`kata-runtime`，或另一个 OCI-compatible 实现。之后，检查环境是 **rootful 还是 rootless**，**user namespaces** 是否激活，是否共享任何 **host namespaces**，剩余的 **capabilities** 是什么，**seccomp** 是否启用，**MAC policy** 是否真正生效，是否存在 **危险的 mounts 或 sockets**，以及该进程是否可以与 container runtime API 交互。

这些答案比基础 image 名称本身能告诉你更多关于真实安全姿态的信息。在许多评估中，仅凭理解最终的 container 配置，你就可以在阅读任何应用文件之前预测可能的 breakout 家族。

## Coverage

本节涵盖了以容器为中心组织的旧 Docker 相关资料：runtime 和 daemon 暴露、authorization plugins、image trust 与 build secrets、敏感的宿主挂载、distroless workloads、privileged containers，以及通常叠加在 container 执行周围的内核保护。
{{#include ../../../banners/hacktricks-training.md}}
