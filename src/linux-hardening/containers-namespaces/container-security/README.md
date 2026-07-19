# Container Security

{{#include ../../../banners/hacktricks-training.md}}

## Container 实际上是什么

定义 Container 的一种实用方式是：Container 是一棵**普通的 Linux 进程树**，它按照特定的 OCI-style 配置启动，因此只能看到受控的文件系统、受控的一组 kernel 资源，以及受限的权限模型。该进程可能认为自己是 PID 1，可能认为自己拥有独立的 network stack，可能认为自己拥有独立的 hostname 和 IPC 资源，甚至可能以 root 身份运行在自己的 user namespace 中。但在底层，它仍然是一个由 kernel 像调度其他进程一样进行调度的 host 进程。

这就是为什么 Container Security 实际上是在研究这种假象是如何构建的，以及它如何失效。如果 mount namespace 不够严格，该进程可能看到 host filesystem。如果不存在或禁用了 user namespace，Container 内的 root 可能与 host 上的 root 过于接近。如果 seccomp 处于 unconfined 状态且 capability set 过于宽泛，该进程可能访问本应无法触及的 syscall 和特权 kernel 功能。如果 runtime socket 被挂载到 Container 内，Container 甚至不需要 kernel breakout，因为它可以直接请求 runtime 启动一个权限更高的 sibling container，或者直接挂载 host root filesystem。

## Container 与 Virtual Machine 的区别

VM 通常拥有自己的 kernel 和 hardware abstraction boundary。这意味着 guest kernel 即使崩溃、panic 或被利用，也不会自动意味着攻击者能够直接控制 host kernel。Container 不会获得独立的 kernel。相反，它获得的是对 host 使用的同一个 kernel 经过严格过滤并通过 namespace 隔离的视图。因此，Container 通常更轻量、启动更快、更容易在一台机器上高密度部署，也更适合短生命周期的 application deployment。代价是，其 isolation boundary 更直接地依赖正确的 host 和 runtime 配置。

这并不意味着 Container 是“不安全的”，而 VM 是“安全的”。这意味着两者的 security model 不同。一个配置良好的 Container stack，如果采用 rootless execution、user namespace、默认 seccomp、严格的 capability set、不共享 host namespace，并实施强制的 SELinux 或 AppArmor，可以非常稳健。相反，一个使用 `--privileged` 启动、共享 host PID/network、在内部挂载 Docker socket，并对 `/` 使用可写 bind mount 的 Container，在功能上更接近 host root access，而不是安全隔离的 application sandbox。差异来自启用或禁用的各个 layer。

读者还应了解一种中间形态，因为它在真实环境中越来越常见。**Sandboxed container runtimes**，例如 **gVisor** 和 **Kata Containers**，会有意将 boundary 加固到超出 classic `runc` container 的程度。gVisor 在 workload 与许多 host kernel interface 之间加入 userspace kernel layer，而 Kata 则在 lightweight virtual machine 中启动 workload。它们仍然通过 Container ecosystem 和 orchestration workflow 使用，但其 security properties 与 plain OCI runtimes 不同，不应将它们与“普通 Docker containers”简单归为一类，仿佛所有行为都相同。

## Container Stack：多个 Layer，而不是单一 Layer

当有人说“这个 Container 不安全”时，一个有用的后续问题是：**是哪一个 layer 导致它不安全？** 一个 Containerized workload 通常是多个组件协同工作的结果。

在最上层，通常存在一个 **image build layer**，例如 BuildKit、Buildah 或 Kaniko，用于创建 OCI image 和 metadata。在 low-level runtime 之上，可能还有一个 **engine 或 manager**，例如 Docker Engine、Podman、containerd、CRI-O、Incus 或 systemd-nspawn。在 cluster environment 中，还可能存在一个 **orchestrator**，例如 Kubernetes，它通过 workload configuration 决定所请求的 security posture。最后，真正执行 namespaces、cgroups、seccomp 和 MAC policy 的是 **kernel**。

这种分层模型对于理解 defaults 非常重要。一个 restriction 可能由 Kubernetes 请求，经由 containerd 或 CRI-O 通过 CRI 转换，再由 runtime wrapper 转换为 OCI spec，最后由 `runc`、`crun`、`runsc` 或其他 runtime 针对 kernel 执行。当不同 environment 之间的 defaults 不同时，通常是因为其中某个 layer 改变了最终 configuration。因此，同一种 mechanism 可能在 Docker 或 Podman 中表现为 CLI flag，在 Kubernetes 中表现为 Pod 或 `securityContext` field，在 low-level runtime stack 中则表现为为 workload 生成的 OCI configuration。出于这个原因，本节中的 CLI examples 应理解为**针对特定 runtime 的通用 Container concept 语法**，而不是每个 tool 都支持的 universal flags。

## 真正的 Container Security Boundary

实际上，Container Security 来自**相互叠加的 controls**，而不是某一个完美的 control。Namespaces 隔离可见性。cgroups 管理并限制 resource usage。Capabilities 降低一个看似拥有特权的进程实际能够执行的操作。seccomp 在危险 syscall 到达 kernel 之前将其阻止。AppArmor 和 SELinux 在普通 DAC checks 之上增加 Mandatory Access Control。`no_new_privs`、masked procfs paths 和 read-only system paths 使常见的 privilege abuse 和 proc/sys abuse chains 更难实现。Runtime 本身也很重要，因为它决定如何创建 mounts、sockets、labels 和 namespace joins。

这就是为什么许多 Container Security 文档看起来似乎在重复。相同的 escape chain 往往同时依赖多个 mechanism。例如，可写的 host bind mount 本身就很危险，但如果 Container 同时以 host 上真正的 root 身份运行、拥有 `CAP_SYS_ADMIN`、未受 seccomp 限制，且没有 SELinux 或 AppArmor 约束，风险会大幅增加。同样，host PID sharing 是一种严重暴露，但当它与 `CAP_SYS_PTRACE`、较弱的 procfs protections 或 `nsenter` 等 namespace-entry tools 结合时，对攻击者的价值会显著提高。因此，正确记录这一主题的方式，不是在每个页面重复同一个 attack，而是解释每个 layer 如何共同构成最终的 boundary。

## 如何阅读本节

本节按照从最通用的 concepts 到最具体的 concepts 的顺序组织。

先从 runtime 和 ecosystem overview 开始：

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

Namespace pages 分别解释 kernel isolation primitives：

{{#ref}}
protections/namespaces/
{{#endref}}

关于 cgroups、capabilities、seccomp、AppArmor、SELinux、`no_new_privs`、masked paths 和 read-only system paths 的页面，解释通常叠加在 namespaces 之上的 mechanisms：

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

评估一个 Containerized target 时，与其立即跳转到著名的 escape PoCs，不如先提出一组精确的 technical questions。首先识别 **stack**：Docker、Podman、containerd、CRI-O、Incus/LXC、systemd-nspawn、Apptainer，或其他更专业的 stack。然后识别 **runtime**：`runc`、`crun`、`runsc`、`kata-runtime`，或其他 OCI-compatible implementation。之后检查 environment 是 **rootful 还是 rootless**，**user namespaces** 是否 active，是否共享任何 **host namespaces**，还剩下哪些 **capabilities**，**seccomp** 是否 enabled，**MAC policy** 是否确实处于 enforcing 状态，是否存在 **dangerous mounts 或 sockets**，以及该进程是否能够与 Container runtime API 交互。

这些答案比 base image name 更能说明真实的 security posture。在许多 assessment 中，只要理解最终的 Container configuration，即使还没有读取任何 application file，也可以预测可能的 breakout family。

## Coverage

本节覆盖旧有的、以 Docker 为重点的 material，并按照 Container-oriented organization 重新组织：runtime 和 daemon exposure、authorization plugins、image trust 和 build secrets、sensitive host mounts、distroless workloads、privileged containers，以及通常围绕 Container execution 叠加的 kernel protections。
{{#include ../../../banners/hacktricks-training.md}}
