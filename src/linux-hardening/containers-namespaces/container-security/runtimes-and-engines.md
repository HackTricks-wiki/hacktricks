# Container Runtimes、Engines、Builders 和 Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security 中最大的混淆来源之一，是多个完全不同的组件经常被统称为同一个词。"Docker" 可能指 image format、CLI、daemon、build system、runtime stack，或者泛指 containers。对于安全工作而言，这种歧义会带来问题，因为不同层负责不同的保护机制。由错误 bind mount 导致的 breakout，与由 low-level runtime bug 导致的 breakout 并不是一回事；这两者也都不同于 Kubernetes 中的 cluster policy 配置错误。

本页面按照角色划分整个生态，以便本节后续内容能够准确说明某项保护或弱点实际存在于哪个位置。

## OCI 作为通用语言

现代 Linux container stacks 通常可以互操作，因为它们遵循一组 OCI specifications。**OCI Image Specification** 描述 image 和 layer 的表示方式。**OCI Runtime Specification** 描述 runtime 应如何启动 process，包括 namespaces、mounts、cgroups 和 security settings。**OCI Distribution Specification** 规范化了 registry 暴露内容的方式。

这很重要，因为它解释了为什么使用某个工具构建的 container image 通常可以使用另一个工具运行，也解释了为什么多个 engines 可以共享同一个 low-level runtime。这也说明了为什么不同产品的 security behavior 可能看起来相似：其中许多产品都在构建相同的 OCI runtime configuration，并将其交给同一小组 runtimes。

## Low-Level OCI Runtimes

low-level runtime 是最接近 kernel boundary 的组件。它实际负责创建 namespaces、写入 cgroup settings、应用 capabilities 和 seccomp filters，最后对 container process 执行 `execve()`。当人们从机制层面讨论 "container isolation" 时，通常指的就是这一层，即使他们没有明确说明。

### `runc`

`runc` 是 reference OCI runtime，仍然是最知名的实现。它被广泛用于 Docker、containerd 以及许多 Kubernetes deployments。大量公开研究和 exploitation material 都针对 `runc`-style environments，原因很简单：它们非常常见，并且 `runc` 定义了许多人理解 Linux container 时所依据的 baseline。因此，理解 `runc` 能够为经典 container isolation 提供良好的 mental model。

### `crun`

`crun` 是另一个 OCI runtime，使用 C 编写，并广泛用于现代 Podman environments。它通常因良好的 cgroup v2 支持、强大的 rootless ergonomics 和较低的 overhead 而受到好评。从安全角度看，重要的不是它使用了不同的语言编写，而是它仍然扮演着相同的角色：将 OCI configuration 转换为 kernel 下运行的 process tree。rootless Podman workflow 往往感觉更安全，并不是因为 `crun` 能够神奇地解决所有问题，而是因为其周围的整体 stack 通常更加侧重于 user namespaces 和 least privilege。

### 来自 gVisor 的 `runsc`

`runsc` 是 gVisor 使用的 runtime。在这里，boundary 的含义发生了实质变化。gVisor 不再像通常情况那样将大多数 syscalls 直接传递给 host kernel，而是插入一个 userspace kernel layer，对 Linux interface 的大部分内容进行 emulation 或 mediation。其结果不是一个仅添加了少量 flags 的普通 `runc` container，而是一种不同的 sandbox design，目的是减少 host-kernel attack surface。Compatibility 和 performance tradeoffs 是该设计的一部分，因此使用 `runsc` 的 environments 应当与普通 OCI runtime environments 分开记录。

### `kata-runtime`

Kata Containers 通过在 lightweight virtual machine 中启动 workload，进一步推进了 boundary。就管理层面而言，它看起来仍然可能是一个 container deployment，orchestration layers 也可能仍将其视为 container，但底层 isolation boundary 更接近 virtualization，而不是经典的共享 host kernel 的 container。当希望获得更强的 tenant isolation，同时又不放弃以 container 为中心的 workflows 时，Kata 会非常有用。

## Engines 和 Container Managers

如果说 low-level runtime 是直接与 kernel 通信的组件，那么 engine 或 manager 就是用户和 operators 通常交互的组件。它负责 image pulls、metadata、logs、networks、volumes、lifecycle operations 以及 API exposure。这一层极其重要，因为许多现实中的 compromises 都发生在这里：即使 low-level runtime 本身完全正常，访问 runtime socket 或 daemon API 也可能等同于取得 host compromise。

### Docker Engine

Docker Engine 是开发者最熟悉的 container platform，也是 container vocabulary 变得如此 Docker 化的原因之一。典型路径是从 `docker` CLI 到 `dockerd`，再由后者协调 `containerd` 和 OCI runtime 等 lower-level components。历史上，Docker deployments 通常是 **rootful** 的，因此访问 Docker socket 会成为非常强大的 primitive。这也是大量实际 privilege-escalation material 聚焦于 `docker.sock` 的原因：如果某个 process 能够要求 `dockerd` 创建 privileged container、挂载 host paths 或加入 host namespaces，那么它可能根本不需要 kernel exploit。

### Podman

Podman 围绕更加 daemonless 的 model 设计。在 operational 层面，这有助于强化这样一种理念：containers 只是通过标准 Linux mechanisms 管理的 processes，而不是由一个长期运行的 privileged daemon 管理。与许多人最初接触的经典 Docker deployments 相比，Podman 也拥有更强的 **rootless** 支持。这并不意味着 Podman 自动安全，但它会显著改变默认 risk profile，尤其是在结合 user namespaces、SELinux 和 `crun` 时。

### containerd

containerd 是许多现代 stacks 中的核心 runtime management component。它被 Docker 使用，同时也是主要的 Kubernetes runtime backends 之一。它暴露 powerful APIs，管理 images 和 snapshots，并将最终的 process creation 委托给 low-level runtime。关于 containerd 的 security discussions 应强调：访问 containerd socket 或 `ctr`/`nerdctl` functionality，可能与访问 Docker API 一样危险，即使其 interface 和 workflow 感觉不那么 "developer friendly"。

### CRI-O

CRI-O 的定位比 Docker Engine 更专一。它不是一个通用的 developer platform，而是围绕干净地实现 Kubernetes Container Runtime Interface 构建的。因此，它在 Kubernetes distributions 以及 OpenShift 等以 SELinux 为主的 ecosystems 中尤其常见。从安全角度看，这种更窄的 scope 很有用，因为它减少了 conceptual clutter：CRI-O 明确属于 "为 Kubernetes 运行 containers" 这一层，而不是一个无所不包的平台。

### Incus、LXD 和 LXC

Incus/LXD/LXC systems 应与 Docker-style application containers 分开考虑，因为它们经常被用作 **system containers**。system container 通常应当更像一台 lightweight machine，拥有更完整的 userspace、长期运行的 services、更丰富的 device exposure 以及更广泛的 host integration。它们使用的 isolation mechanisms 仍然是 kernel primitives，但 operational expectations 不同。因此，这里的 misconfigurations 往往不像是 "bad app-container defaults"，而更像是 lightweight virtualization 或 host delegation 中的错误。

### systemd-nspawn

systemd-nspawn 位于一个有趣的位置，因为它是 systemd-native，并且非常适合 testing、debugging 以及运行类似 OS 的 environments。它不是 cloud-native production runtime 的主流选择，但在 labs 和以 distro 为中心的 environments 中出现得足够频繁，因此值得提及。从 security analysis 的角度看，它再次提醒我们，"container" 这一概念横跨多个 ecosystems 和 operational styles。

### Apptainer / Singularity

Apptainer（原名 Singularity）在 research 和 HPC environments 中很常见。它的 trust assumptions、user workflow 和 execution model，与以 Docker/Kubernetes 为中心的 stacks 存在重要差异。特别是，这些 environments 通常非常重视让 users 能够运行 packaged workloads，同时不向其授予广泛的 privileged container-management powers。如果 reviewer 假设每个 container environment 本质上都是 "运行在 server 上的 Docker"，就会严重误解这些 deployments。

## Build-Time Tooling

许多 security discussions 只讨论 runtime，但 build-time tooling 同样重要，因为它决定了 image contents、build secrets exposure，以及最终 artifact 中会嵌入多少 trusted context。

**BuildKit** 和 `docker buildx` 是现代 build backends，支持 caching、secret mounting、SSH forwarding 以及 multi-platform builds 等功能。这些功能很有用，但从安全角度看，它们也会产生一些风险点：secrets 可能 leak 到 image layers 中，或者过于宽泛的 build context 可能暴露本不应被包含的 files。**Buildah** 在 OCI-native ecosystems 中扮演类似角色，尤其是在 Podman 周边；而 **Kaniko** 经常用于不希望向 build pipeline 授予 privileged Docker daemon 的 CI environments。

关键结论是，image creation 和 image execution 是两个不同阶段，但 weak build pipeline 可能会在 container 启动之前很久，就造成 weak runtime posture。

## Orchestration 是另一层，而不是 Runtime

不应在 mental model 中将 Kubernetes 等同于 runtime 本身。Kubernetes 是 orchestrator。它负责调度 Pods、存储 desired state，并通过 workload configuration 表达 security policy。随后 kubelet 会与 containerd 或 CRI-O 等 CRI implementation 通信，而后者再调用 `runc`、`crun`、`runsc` 或 `kata-runtime` 等 low-level runtime。

这种分离很重要，因为许多人会错误地将某项 protection 归因于 "Kubernetes"，而实际上它是由 node runtime 执行的；或者将某种 behavior 归咎于 "containerd defaults"，而该 behavior 实际来自 Pod spec。实践中，最终的 security posture 是多部分组合的结果：orchestrator 发出请求，runtime stack 对其进行转换，最后由 kernel 执行。

## 为什么 Assessment 期间识别 Runtime 很重要

如果尽早识别 engine 和 runtime，后续许多 observations 都会更容易解释。rootless Podman container 表明 user namespaces 很可能参与其中。挂载到 workload 中的 Docker socket 表明，基于 API 的 privilege escalation 可能是一条现实路径。CRI-O/OpenShift node 应立即让你想到 SELinux labels 和 restricted workload policy。gVisor 或 Kata environment 则应使你更加谨慎，不要假设经典的 `runc` breakout PoC 会以相同方式运行。

因此，container assessment 的第一步之一，始终应当回答两个简单问题：**哪个 component 正在管理 container**，以及 **实际启动该 process 的 runtime 是哪个**。明确这两个答案后，通常就会更容易分析整个 environment。

## Runtime Vulnerabilities

并非所有 container escapes 都源自 operator misconfiguration。有时，runtime 本身就是 vulnerable component。这一点很重要，因为某个 workload 即使使用了看似谨慎的 configuration，仍可能通过 low-level runtime flaw 暴露出来。

经典示例是 `runc` 中的 **CVE-2019-5736**。恶意 container 可以覆盖 host 上的 `runc` binary，然后等待后续的 `docker exec` 或类似 runtime invocation 触发 attacker-controlled code。该 exploit path 与简单的 bind-mount 或 capability mistake 有很大区别，因为它利用了 runtime 在处理 exec 时重新进入 container process space 的方式。<sup>[[1]](#references)</sup>

从 red-team 角度看，一个最小 reproduction workflow 是：
```bash
go build main.go
./main
```
然后，在 host 上：
```bash
docker exec -it <container-name> /bin/sh
```
关键教训并不是确切的历史漏洞利用实现，而是评估层面的影响：如果 runtime 版本存在漏洞，即使可见的容器配置看起来并没有明显弱点，普通的容器内代码执行也可能足以 compromise 主机。

近期的 runtime CVE（例如 `runc` 中的 `CVE-2024-21626`、BuildKit mount 竞态条件以及 containerd 解析漏洞）进一步印证了这一点。runtime 版本和补丁级别属于安全边界的一部分，而不仅仅是维护层面的琐事。

## 参考资料

- [1] [Breaking out of Docker via runC – Explaining CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)

{{#include ../../../banners/hacktricks-training.md}}
