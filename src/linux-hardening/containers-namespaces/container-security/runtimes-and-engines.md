# 容器 Runtimes、引擎、构建器和沙箱

{{#include ../../../banners/hacktricks-training.md}}

容器安全领域最容易引起混淆的原因之一，是人们经常把几个完全不同的组件都统称为同一个词。“Docker”可能指镜像格式、CLI、daemon、构建系统、runtime stack，也可能只是泛指容器。对于安全工作而言，这种歧义会带来问题，因为不同层负责不同的保护机制。由错误的 bind mount 导致的 breakout，与低层 runtime 漏洞导致的 breakout 并不是一回事；这两者也都不同于 Kubernetes 中的集群策略错误。

本页按职责划分生态系统，以便本节后续内容能准确说明某项保护或弱点实际存在于哪一层。

## OCI 作为通用语言

现代 Linux 容器栈通常可以互通，因为它们采用一组 OCI 规范。**OCI Image Specification** 描述镜像和层的表示方式。**OCI Runtime Specification** 描述 runtime 应如何启动进程，包括 namespaces、mounts、cgroups 和安全设置。**OCI Distribution Specification** 则标准化了 registry 提供内容的方式。

这很重要，因为它解释了为什么用一种工具构建的容器镜像通常可以用另一种工具运行，也解释了为什么多个引擎可以共用同一个低层 runtime。它还说明了为什么不同产品的安全行为看起来可能相似：其中许多产品都会构建相同的 OCI runtime 配置，并将其交给同一小部分 runtimes。

## 低层 OCI Runtimes

低层 runtime 是最接近内核边界的组件。它负责实际创建 namespaces、写入 cgroup 设置、应用 capabilities 和 seccomp filters，最后对容器进程调用 `execve()`。人们在机制层面讨论“容器隔离”时，通常指的就是这一层，即使他们没有明确说出来。

### `runc`

`runc` 是 OCI runtime 的参考实现，也是最知名的实现。它广泛用于 Docker、containerd 和许多 Kubernetes 部署中。许多公开研究和 exploit 资料都针对 `runc` 风格的环境，原因很简单：这类环境很常见，而且 `runc` 定义了许多人脑海中 Linux 容器的基准模型。因此，理解 `runc` 能让读者对经典容器隔离建立扎实的心智模型。

### `crun`

`crun` 是另一个 OCI runtime，以 C 编写，在现代 Podman 环境中广泛使用。它常因良好的 cgroup v2 支持、出色的 rootless 易用性和较低开销而受到称赞。从安全角度来看，重要的不是它使用了不同的编程语言，而是它仍然承担相同的职责：将 OCI 配置转换为内核下运行的进程树。rootless Podman 工作流往往让人感觉更安全，并不是因为 `crun` 能神奇地解决所有问题，而是因为它周围的整体栈通常更强调 user namespaces 和最小权限。

### gVisor 的 `runsc`

`runsc` 是 gVisor 使用的 runtime。在这里，隔离边界的含义发生了实质变化。gVisor 不会像通常那样把大多数 syscalls 直接传递给宿主机内核，而是插入一个 userspace kernel 层，用来模拟或中介 Linux 接口的大部分功能。最终得到的并不是一个只加了几个额外 flags 的普通 `runc` 容器，而是一种不同的 sandbox 设计，目的是减少宿主机内核的攻击面。兼容性和性能上的取舍是这一设计的一部分，因此使用 `runsc` 的环境应与普通 OCI runtime 环境区别记录。

### `kata-runtime`

Kata Containers 通过在轻量级虚拟机内运行工作负载，进一步推进了隔离边界。从管理角度来看，这仍可能像一次容器部署；编排层也可能仍将其视为容器，但底层隔离边界更接近虚拟化，而不是共享宿主机内核的经典容器。当希望加强租户隔离但又不想放弃以容器为中心的工作流时，Kata 就很有用。

## 引擎和容器管理器

如果说低层 runtime 是直接与内核交互的组件，那么引擎或管理器就是用户和运维人员通常会接触的组件。它负责拉取镜像、管理元数据、日志、网络和 volumes，处理生命周期操作，并暴露 API。这一层非常重要，因为许多现实中的入侵都发生在这里：即使低层 runtime 本身完全正常，访问 runtime socket 或 daemon API 也可能等同于攻陷宿主机。

### Docker Engine

Docker Engine 是开发者最熟悉的容器平台，也是容器术语逐渐变得以 Docker 为中心的原因之一。典型调用路径是 `docker` CLI 到 `dockerd`，再由后者协调 `containerd` 和 OCI runtime 等低层组件。历史上，Docker 部署通常是 **rootful**，因此访问 Docker socket 是一种权限极高的能力。这就是为什么大量实际的提权资料都聚焦于 `docker.sock`：如果进程能要求 `dockerd` 创建特权容器、挂载宿主机路径或加入宿主机 namespaces，它可能根本不需要内核 exploit。

应按 major、minor 和 patch 部分比较版本号，而不要去掉点号：尽管 minor 部分带有前导零，`18.09.1` 仍比 `18.09.2` 和 `18.09.4` 更旧。Docker 的 [18.09 release notes](https://docs.docker.com/engine/release-notes/18.09/) 记录了 18.09.2 中捆绑的 `runc` CVE-2019-5736 修复，以及 18.09.4 中的 build-reference CVE-2019-13139 修复。这些版本信息只能作为线索，并不能证明存在可利用的漏洞。相同的 release notes 还提醒，daemon、client 和 runtime 是单独打包的，因此应同时检查已安装的 runtime 和厂商回补补丁，而不能只看 daemon 版本；此外，build-reference 问题还要求能够访问受影响的构建工作流，并存在攻击者可控的输入。

### Podman

Podman 的设计采用了更偏向无 daemon 的模式。从运维角度看，这有助于强化这样一种理念：容器只是通过标准 Linux 机制管理的进程，而不是由一个长期运行的特权 daemon 管理。与许多人最初接触的经典 Docker 部署相比，Podman 对 **rootless** 的支持也强得多。这并不意味着 Podman 自动安全，但它会显著改变默认风险状况，特别是在与 user namespaces、SELinux 和 `crun` 配合使用时。

### containerd

containerd 是许多现代栈中的核心 runtime 管理组件。它用于 Docker，也是一种占主导地位的 Kubernetes runtime 后端。它暴露强大的 API，管理镜像和 snapshots，并将最终的进程创建委托给低层 runtime。讨论 containerd 安全性时，应强调访问 containerd socket 或 `ctr`/`nerdctl` 功能可能与访问 Docker API 一样危险，即使其接口和工作流看起来没那么“面向开发者”。

### CRI-O

CRI-O 的用途比 Docker Engine 更专一。它并不是通用开发者平台，而是围绕干净实现 Kubernetes Container Runtime Interface 而构建的。因此，它在 Kubernetes 发行版和 OpenShift 等以 SELinux 为重点的生态系统中尤为常见。从安全角度来看，这种较窄的范围很有用，因为它减少了概念上的混杂：CRI-O 明确属于“为 Kubernetes 运行容器”这一层，而不是一个包罗万象的平台。

当 Kubernetes 节点使用 CRI-O 时，应检查**节点当前启用的 CRI-O 版本**，并确认当前身份是否能在会调度到该节点的 namespace 中创建 Pods。[CVE-2022-0811](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) 允许经过构造的 Pod sysctl 值更改宿主机内核参数，并在受影响的版本中获得宿主机 root 权限。上游公告列出了已修复版本和临时缓解措施。本地运行 `crio --version` 可能看不到嵌套在 Minikube 或其他节点容器中的 runtime；可读的 Minikube 启动日志或许能提供版本线索，但这只是历史证据，不能证明当前运行的 runtime 版本或其补丁状态。在将其视为可触发的提权路径之前，应确认实际节点 runtime、Pod 创建授权、准入规则，以及相关的 seccomp 和 user namespace 边界。

此外，还可以直接在本地审查 `pinns`：[研究人员指出，无需 Kubernetes 也能调用存在缺陷的 helper](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/)。检查当前账户能否执行 root 所有的 setuid `pinns`，NoNewPrivs 或 `nosuid` mount 是否会阻止该权限转换，以及已安装的 **helper build** 是否缺少修复。 [上游公告](https://github.com/cri-o/cri-o/security/advisories/GHSA-6x2m-w449-qwx7) 列出了已修复的版本，但 daemon 显示的版本本身无法证明安装的是哪个 helper 二进制文件，发行版回补补丁也可能改变受影响范围。setuid 文件只能算是一个候选目标；在常规枚举期间，不要运行它，而应验证 helper 来源、配置和宿主机 sysctl 行为。

### Incus、LXD 和 LXC

Incus/LXD/LXC 系统值得与 Docker 风格的应用容器区分开来，因为它们经常用于**系统容器**。系统容器通常需要表现得更像一台轻量级机器，拥有更完整的 userspace、长期运行的服务、更丰富的设备暴露，以及更深入的宿主机集成。其隔离机制仍然使用内核原语，但运维方面的预期有所不同。因此，这里的错误配置往往不像是“应用容器默认设置不当”，而更像是轻量级虚拟化或宿主机委派中的错误。

### systemd-nspawn

systemd-nspawn 占据着一个有趣的位置，因为它原生集成于 systemd，非常适合测试、调试和运行类似操作系统的环境。它不是云原生生产环境中的主流 runtime，但在实验环境和以发行版为中心的环境中出现得足够频繁，值得一提。对于安全分析而言，它再次提醒我们，“容器”这一概念涵盖了多个生态系统和运维风格。

### Apptainer / Singularity

Apptainer（前身为 Singularity）在研究和 HPC 环境中很常见。与以 Docker/Kubernetes 为中心的栈相比，它的信任假设、用户工作流和执行模型都有重要差异。尤其是，这些环境通常非常重视让用户运行打包好的工作负载，同时不赋予他们广泛的特权容器管理能力。如果审查人员把每种容器环境都当成“服务器上的 Docker”，就会严重误解这些部署。

## 构建时工具

许多安全讨论只谈运行时，但构建时工具也很重要，因为它决定了镜像内容、构建 secrets 的暴露情况，以及最终产物中包含了多少受信任上下文。

**BuildKit** 和 `docker buildx` 是现代构建后端，支持缓存、secret 挂载、SSH 转发和多平台构建等功能。这些功能很有用，但从安全角度来看，它们也可能造成 secrets 泄漏到镜像层中，或者让过于宽泛的构建上下文暴露本不该包含的文件。**Buildah** 在 OCI 原生生态系统中承担类似职责，尤其常见于 Podman 环境；而 **Kaniko** 常用于不希望向构建流水线授予特权 Docker daemon 的 CI 环境。

关键在于，镜像创建和镜像运行是不同的阶段，但薄弱的构建流水线可能会在容器启动之前，就造成薄弱的运行时安全状况。

## 编排是另一层，不是 Runtime

不要在概念上把 Kubernetes 等同于 runtime。Kubernetes 是编排器。它负责调度 Pods、存储期望状态，并通过工作负载配置表达安全策略。随后，kubelet 会与 containerd 或 CRI-O 等 CRI 实现交互，而这些组件又会调用 `runc`、`crun`、`runsc` 或 `kata-runtime` 等低层 runtime。

这种区分很重要，因为很多人会错误地把某项保护归因于“Kubernetes”，而实际上它是由节点 runtime 强制执行的；或者他们会把来自 Pod spec 的行为归咎于“containerd 默认设置”。实际上，最终的安全状况是多个组件共同作用的结果：编排器发出请求，runtime stack 对其进行转换，最后由内核强制执行。

## 评估时识别 Runtime 的重要性

如果尽早识别引擎和 runtime，之后的许多观察结果都会更容易理解。rootless Podman 容器意味着 user namespaces 很可能是其中一部分。挂载到工作负载中的 Docker socket 表明，基于 API 的提权很可能是一条现实路径。CRI-O/OpenShift 节点应立即让你想到 SELinux labels 和受限工作负载策略。gVisor 或 Kata 环境则应让你更谨慎地看待经典 `runc` breakout PoC，不能假设它会以同样的方式运行。

因此，容器评估的首要步骤之一，应该始终是回答两个简单问题：**哪个组件在管理容器**，以及**哪个 runtime 实际启动了进程**。明确这两个答案后，通常就能更轻松地分析环境中的其他部分。

## Runtime 漏洞

并非每次容器 escape 都是由运维人员的错误配置造成的。有时，runtime 本身就是存在漏洞的组件。这一点很重要，因为即使工作负载看起来采用了谨慎的配置，仍可能受到低层 runtime 漏洞的影响。

经典例子是 `runc` 中的 **CVE-2019-5736**：恶意容器可以覆盖宿主机上的 `runc` 二进制文件，然后等待后续的 `docker exec` 或类似 runtime 调用触发攻击者控制的代码。与简单的 bind-mount 或 capability 配置错误相比，这条 exploit 路径截然不同，因为它利用了 runtime 在处理 exec 时重新进入容器进程空间的方式。<sup>[[1]](#references)</sup>

从 red-team 角度出发，最小化复现工作流如下：

```bash
go build main.go
./main
```

然后，从 host 执行：

```bash
docker exec -it <container-name> /bin/sh
```

关键教训不在于具体的历史漏洞利用实现，而在于它对安全评估的影响：如果 runtime 版本存在漏洞，那么即使可见的容器配置看起来并没有明显的薄弱之处，普通的容器内代码执行也可能足以危及主机。

近期的 runtime CVE（例如 `runc` 中的 `CVE-2024-21626`）、BuildKit 挂载竞态以及 containerd 解析漏洞，都进一步印证了这一点。Runtime 版本和补丁级别属于安全边界的一部分，而不只是维护方面的琐事。

## References

- [1] [通过 runC 突破 Docker——解读 CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
