# Container 安全

{{#include ../../../banners/hacktricks-training.md}}

## Container 实际上是什么

定义 Container 的一种实用方式是：Container 是一棵**普通的 Linux 进程树**，它在特定的 OCI-style 配置下启动，因此能够看到受控的文件系统、受控的一组 kernel 资源，以及受限的权限模型。该进程可能认为自己是 PID 1，可能认为自己拥有独立的 network stack，可能认为自己拥有独立的 hostname 和 IPC 资源，甚至可能在自己的 user namespace 中以 root 身份运行。但在底层，它仍然是一个由 kernel 像调度其他进程一样进行调度的 host 进程。

这就是为什么 Container 安全本质上是在研究这种错觉是如何构建的，以及它如何失效。如果 mount namespace 较弱，进程可能会看到 host filesystem。如果 user namespace 不存在或被禁用，Container 内的 root 可能会与 host 上的 root 过于接近地映射。如果 seccomp 未限制且 capability 集过于宽泛，进程可能访问本应无法触及的 syscall 和特权 kernel 功能。如果 runtime socket 被挂载到 Container 内，Container 甚至不需要 kernel breakout，因为它可以直接请求 runtime 启动一个权限更高的 sibling Container，或直接挂载 host root filesystem。

## Container 与 Virtual Machine 的区别

VM 通常拥有自己的 kernel 和 hardware abstraction boundary。这意味着 guest kernel 发生 crash、panic 或遭到利用时，并不会自动意味着攻击者直接控制 host kernel。在 Container 中，workload 不会获得独立的 kernel，而是获得同一个 host 使用的 kernel 的经过严格过滤和 namespace 隔离的视图。因此，Container 通常更轻量、启动更快、更容易在一台机器上高密度部署，也更适合短生命周期的 application 部署。代价是，隔离边界更加直接地依赖 host 和 runtime 的正确配置。

这并不意味着 Container 是“不安全的”，而 VM 是“安全的”。这意味着二者的安全模型不同。一个配置良好的 Container stack，配合 rootless 执行、user namespaces、默认 seccomp、严格的 capability 集、不共享 host namespaces，以及强制执行的 SELinux 或 AppArmor，可以非常稳健。相反，一个使用 `--privileged` 启动、共享 host PID/network、在内部挂载 Docker socket，并且对 `/` 进行可写 bind mount 的 Container，在功能上更接近 host root access，而不是安全隔离的 application sandbox。差异来自启用或禁用的各个层。

读者还应了解一种中间形态，因为它在真实环境中越来越常见。**Sandboxed Container runtimes**，例如 **gVisor** 和 **Kata Containers**，会有意将边界强化到经典 `runc` Container 之上。gVisor 在 workload 与许多 host kernel interfaces 之间加入 userspace kernel 层，而 Kata 则在轻量级 virtual machine 中启动 workload。这些方案仍通过 Container 生态和 orchestration workflow 使用，但其安全属性不同于普通 OCI runtimes，不应将它们与“普通 Docker containers”简单归为一类，仿佛所有行为都相同。

## Container Stack：多个层，而非单一层

当有人说“这个 Container 不安全”时，一个有用的后续问题是：**是哪一层导致它不安全？** 一个 Containerized workload 通常是多个组件协同工作的结果。

最上层通常是 **image build layer**，例如 BuildKit、Buildah 或 Kaniko，它负责创建 OCI image 和 metadata。在 low-level runtime 之上，可能存在 **engine 或 manager**，例如 Docker Engine、Podman、containerd、CRI-O、Incus 或 systemd-nspawn。在 cluster 环境中，还可能有 **orchestrator**，例如 Kubernetes，通过 workload configuration 决定所请求的 security posture。最后，真正执行 namespaces、cgroups、seccomp 和 MAC policy 的是 **kernel**。

理解 defaults 时，这种分层模型非常重要。一个 restriction 可能由 Kubernetes 请求，经由 containerd 或 CRI-O 通过 CRI 传递，再由 runtime wrapper 转换为 OCI spec，最后由 `runc`、`crun`、`runsc` 或其他 runtime 针对 kernel 执行。当不同环境中的 defaults 存在差异时，通常是因为其中某一层改变了最终 configuration。因此，同一种机制可能在 Docker 或 Podman 中表现为 CLI flag，在 Kubernetes 中表现为 Pod 或 `securityContext` field，在更底层的 runtime stack 中则表现为为 workload 生成的 OCI configuration。因此，本节中的 CLI examples 应理解为**某个 runtime 特有的、用于表达通用 Container 概念的 syntax**，而不是每个 tool 都支持的 universal flags。

## 真正的 Container 安全边界

实际上，Container 安全来自**相互叠加的 controls**，而不是某个单一的完美 control。Namespaces 隔离可见性。cgroups 管理并限制资源使用。Capabilities 降低一个看似拥有特权的进程实际能够执行的操作。seccomp 在危险 syscalls 到达 kernel 之前将其阻断。AppArmor 和 SELinux 在普通 DAC checks 之上增加 Mandatory Access Control。`no_new_privs`、masked procfs paths 和 read-only system paths 让常见的 privilege abuse 和 proc/sys abuse chains 更难实现。Runtime 本身同样重要，因为它决定 mounts、sockets、labels 和 namespace joins 的创建方式。

这就是为什么许多 Container 安全文档看起来似乎在重复内容。同一条 escape chain 往往同时依赖多个机制。例如，可写的 host bind mount 本身就很危险，但如果 Container 同时以 host 上的真实 root 身份运行、拥有 `CAP_SYS_ADMIN`、不受 seccomp 限制，并且未受到 SELinux 或 AppArmor 约束，情况会恶化得多。同样，host PID sharing 是一种严重暴露，但当它与 `CAP_SYS_PTRACE`、薄弱的 procfs protections 或 `nsenter` 等 namespace-entry tools 结合时，对 attacker 的利用价值会显著增加。因此，正确记录该主题的方式不是在每个页面重复同一种 attack，而是解释每一层如何共同构成最终边界。

## 如何阅读本节

本节按照从最通用概念到最具体概念的顺序组织。

先从 runtime 和生态概览开始：

{{#ref}}
runtimes-and-engines.md
{{#endref}}

然后查看经常决定 attacker 是否根本需要进行 kernel escape 的 control planes 和 supply-chain surfaces：

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

然后进入 protection model：

{{#ref}}
protections/
{{#endref}}

Namespace 页面会分别解释 kernel isolation primitives：

{{#ref}}
protections/namespaces/
{{#endref}}

关于 cgroups、capabilities、seccomp、AppArmor、SELinux、`no_new_privs`、masked paths 和 read-only system paths 的页面，会解释通常叠加在 namespaces 之上的 mechanisms：

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

## 良好的初始 Enumeration 思路

评估 Containerized target 时，与其立即跳到知名的 escape PoCs，不如先提出一组精准的 technical questions，这样更有用。首先，识别 **stack**：Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer，或其他更专门的方案。然后识别 **runtime**：`runc`、`crun`、`runsc`、`kata-runtime` 或其他 OCI-compatible implementation。之后检查环境是 **rootful 还是 rootless**、**user namespaces** 是否 active、是否共享任何 **host namespaces**、还剩哪些 **capabilities**、是否启用了 **seccomp**、**MAC policy** 是否确实处于 enforcing 状态、是否存在 **dangerous mounts 或 sockets**，以及进程是否能够与 Container runtime API 交互。

这些答案比 base image name 更能说明真实的 security posture。在许多 assessments 中，只要理解最终的 Container configuration，无需阅读任何 application file，就可以预测可能的 breakout family。

## 覆盖范围

本节涵盖旧有的、以 Docker 为重点的内容，并按照面向 Container 的方式重新组织：runtime 和 daemon exposure、authorization plugins、image trust 和 build secrets、sensitive host mounts、distroless workloads、privileged containers，以及通常围绕 Container execution 叠加的 kernel protections。

{{#include ../../../banners/hacktricks-training.md}}
