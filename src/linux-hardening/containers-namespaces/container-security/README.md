# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## 容器实际上是什么

一种实用的容器定义方式是：容器是一个**普通的 Linux 进程树**，它在特定的 OCI-style 配置下启动，因此只能看到受控的文件系统、受控的一组内核资源，以及受限的权限模型。该进程可能认为自己是 PID 1，可能认为自己拥有独立的网络栈，可能认为自己拥有独立的主机名和 IPC 资源，甚至可能以 root 身份运行在自己的 user namespace 中。但在底层，它仍然是一个由内核像其他进程一样进行调度的主机进程。

这就是为什么 container security 本质上是研究这种假象如何构建，以及它如何失效。如果 mount namespace 不够严格，进程可能看到主机文件系统。如果不存在或禁用了 user namespace，容器内的 root 可能与主机上的 root 过于接近。如果 seccomp 处于 unconfined 状态且 capability 集过于宽泛，进程可能访问本应无法触及的 syscall 和特权内核功能。如果 runtime socket 被挂载到容器内，容器甚至不需要 kernel breakout，因为它可以直接请求 runtime 启动一个权限更高的 sibling container，或者直接挂载主机的 root filesystem。

## 容器与虚拟机的区别

VM 通常拥有自己的 kernel 和 hardware abstraction boundary。这意味着 guest kernel 即使崩溃、panic 或遭到利用，也不会自动意味着攻击者可以直接控制 host kernel。在容器中，工作负载不会获得独立的 kernel。相反，它获得的是对主机使用的同一个 kernel 经过严格过滤并通过 namespace 隔离的视图。因此，容器通常更轻量、启动更快、更容易在一台机器上高密度部署，也更适合短生命周期的应用部署。代价是，其隔离边界更加直接地依赖于正确的主机和 runtime 配置。

这并不意味着容器“不安全”而 VM“安全”。这意味着两者的 security model 不同。一个采用 rootless execution、user namespace、默认 seccomp、严格 capability 集、不共享 host namespace，并由强制 SELinux 或 AppArmor enforcement 的容器栈，可以非常可靠。相反，一个使用 `--privileged` 启动、共享 host PID/network、在容器内挂载 Docker socket，并对 `/` 进行可写 bind mount 的容器，在功能上更接近 host root access，而不是安全隔离的 application sandbox。区别来自启用或禁用的各个层。

此外，还有一个读者应当了解的中间地带，因为它在真实环境中越来越常见。**Sandboxed container runtimes**，例如 **gVisor** 和 **Kata Containers**，会有意将隔离边界强化到传统 `runc` container 之上。gVisor 在工作负载与许多 host kernel interface 之间加入 userspace kernel layer，而 Kata 则在 lightweight virtual machine 中启动工作负载。它们仍然通过 container ecosystem 和 orchestration workflow 使用，但其 security properties 与普通 OCI runtimes 不同，不应将它们简单地归入“普通 Docker containers”，仿佛所有行为都相同。

## Container Stack：多个层，而非单一层

当有人说“这个 container 不安全”时，有用的后续问题是：**是哪一层导致它不安全？** 一个 containerized workload 通常是多个组件协同工作的结果。

最上层通常是 **image build layer**，例如 BuildKit、Buildah 或 Kaniko，它负责创建 OCI image 和 metadata。在 low-level runtime 之上，可能还有 **engine 或 manager**，例如 Docker Engine、Podman、containerd、CRI-O、Incus 或 systemd-nspawn。在 cluster environment 中，还可能有 **orchestrator**，例如 Kubernetes，它通过 workload configuration 决定所请求的 security posture。最后，真正执行 namespaces、cgroups、seccomp 和 MAC policy 的是 **kernel**。

这种分层模型对于理解 defaults 非常重要。一个 restriction 可能由 Kubernetes 请求，经由 containerd 或 CRI-O 通过 CRI 进行转换，再由 runtime wrapper 转换成 OCI spec，最后才由 `runc`、`crun`、`runsc` 或其他 runtime 针对 kernel 执行。当不同环境中的 defaults 存在差异时，通常是因为其中某一层改变了最终 configuration。因此，同一种机制可能在 Docker 或 Podman 中表现为 CLI flag，在 Kubernetes 中表现为 Pod 或 `securityContext` field，在更底层的 runtime stack 中则表现为为 workload 生成的 OCI configuration。因此，本节中的 CLI 示例应理解为**适用于特定 runtime 的通用 container concept 语法**，而不是每个 tool 都支持的 universal flag。

## 真正的 Container Security Boundary

实际上，container security 来自**相互叠加的 controls**，而不是某一个完美的 control。Namespaces 隔离可见性。cgroups 管理并限制资源使用。Capabilities 限制一个看似拥有特权的进程实际能够执行的操作。seccomp 在危险 syscalls 到达 kernel 之前将其阻断。AppArmor 和 SELinux 在常规 DAC checks 之上增加 Mandatory Access Control。`no_new_privs`、masked procfs paths 和 read-only system paths 使常见的 privilege abuse 和 proc/sys abuse chains 更难实现。runtime 本身也很重要，因为它决定 mounts、sockets、labels 和 namespace joins 的创建方式。

这就是为什么许多 container security 文档看起来反复强调相同内容。同一条 escape chain 往往同时依赖多个机制。例如，可写的 host bind mount 本身就很危险，但如果容器还以主机上的真实 root 身份运行、拥有 `CAP_SYS_ADMIN`、未受到 seccomp 限制，且没有 SELinux 或 AppArmor 约束，情况会严重得多。同样，共享 host PID 是一种严重暴露，但当它与 `CAP_SYS_PTRACE`、薄弱的 procfs protections 或 `nsenter` 等 namespace-entry tools 结合时，对攻击者的价值会显著增加。因此，正确记录这一主题的方式不是在每个页面重复同一种 attack，而是解释每一层如何共同构成最终的 boundary。

## 如何阅读本节

本节按照从最通用概念到最具体概念的顺序组织。

首先从 runtime 和 ecosystem overview 开始：

{{#ref}}
runtimes-and-engines.md
{{#endref}}

然后查看经常决定攻击者是否甚至需要 kernel escape 的 control planes 和 supply-chain surfaces：

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

namespace 页面分别解释 kernel isolation primitives：

{{#ref}}
protections/namespaces/
{{#endref}}

关于 cgroups、capabilities、seccomp、AppArmor、SELinux、`no_new_privs`、masked paths 和 read-only system paths 的页面，解释了通常叠加在 namespaces 之上的 mechanisms：

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

评估一个 containerized target 时，与其立即跳转到知名的 escape PoCs，不如先提出一组精确的 technical questions。首先确定 **stack**：Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer，或其他更专业的工具。然后确定 **runtime**：`runc`、`crun`、`runsc`、`kata-runtime`，或其他 OCI-compatible implementation。之后检查环境是 **rootful 还是 rootless**，**user namespaces** 是否启用，是否共享任何 **host namespaces**，还剩哪些 **capabilities**，是否启用 **seccomp**，**MAC policy** 是否实际处于 enforcing 状态，是否存在 **dangerous mounts 或 sockets**，以及进程能否与 container runtime API 交互。

这些答案比 base image name 更能说明真实的 security posture。在许多 assessment 中，仅通过理解最终的 container configuration，无需阅读任何 application file，就可以预测可能的 breakout family。

## Coverage

本节以面向 container 的组织方式，涵盖旧有的 Docker-focused material：runtime 和 daemon exposure、authorization plugins、image trust 和 build secrets、sensitive host mounts、distroless workloads、privileged containers，以及通常围绕 container execution 叠加的 kernel protections。

{{#include ../../../banners/hacktricks-training.md}}
