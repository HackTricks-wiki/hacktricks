# Container Runtimes、Engines、Builders 与 Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security 中最大的困惑来源之一，是多个完全不同的组件经常被统称为同一个词。"Docker" 可能指 image 格式、CLI、daemon、build system、runtime stack，或者泛指 containers 这一概念。对于安全工作而言，这种歧义会带来问题，因为不同层负责不同的保护机制。由错误 bind mount 导致的 breakout，与由 low-level runtime bug 导致的 breakout 并不是一回事，两者也都不同于 Kubernetes 中的 cluster policy 配置错误。

本页面按角色划分整个生态系统，使本节后续内容能够准确说明某个保护机制或弱点究竟存在于哪一层。

## OCI 作为通用语言

现代 Linux container stacks 通常能够互操作，是因为它们遵循一组 OCI specifications。**OCI Image Specification** 描述 image 和 layers 的表示方式。**OCI Runtime Specification** 描述 runtime 应如何启动进程，包括 namespaces、mounts、cgroups 和 security settings。**OCI Distribution Specification** 规定 registries 如何提供内容。

这很重要，因为它解释了为什么使用某个 tool 构建的 container image 通常可以使用另一个 tool 运行，以及为什么多个 engines 可以共享同一个 low-level runtime。这也解释了为什么不同产品的 security behavior 可能看起来相似：它们中的许多产品都在构造相同的 OCI runtime configuration，并将其交给同一小组 runtimes。

## Low-Level OCI Runtimes

low-level runtime 是最接近 kernel boundary 的组件。它负责实际创建 namespaces、写入 cgroup settings、应用 capabilities 和 seccomp filters，最后对 container process 执行 `execve()`。当人们从机械层面讨论 "container isolation" 时，通常指的就是这一层，即使他们没有明确说明。

### `runc`

`runc` 是 reference OCI runtime，仍然是最知名的实现。它被广泛用于 Docker、containerd 以及许多 Kubernetes deployments。大量公开研究和 exploitation material 都针对 `runc`-style environments，原因很简单：它们很常见，而且 `runc` 定义了许多人想象 Linux container 时所想到的 baseline。理解 `runc` 因此能够为读者建立关于经典 container isolation 的良好 mental model。

### `crun`

`crun` 是另一个 OCI runtime，使用 C 编写，并广泛用于现代 Podman environments。它通常因良好的 cgroup v2 支持、出色的 rootless ergonomics 和较低的 overhead 而受到认可。从 security 角度看，关键并不在于它使用了不同的语言编写，而在于它仍然承担相同的角色：将 OCI configuration 转换为 kernel 下运行的 process tree。rootless Podman workflow 通常会让人感觉更安全，并不是因为 `crun` 能够神奇地解决所有问题，而是因为其周围的整体 stack 往往更重视 user namespaces 和 least privilege。

### 来自 gVisor 的 `runsc`

`runsc` 是 gVisor 使用的 runtime。这里的 boundary 发生了实质变化。gVisor 并不是像通常方式那样将大多数 syscalls 直接传递给 host kernel，而是插入一个 userspace kernel layer，对 Linux interface 的很大一部分进行 emulation 或 mediation。其结果并不是一个只增加了几个 flags 的普通 `runc` container，而是一种不同的 sandbox design，目的是减少 host-kernel attack surface。Compatibility 和 performance tradeoffs 都属于该设计的一部分，因此使用 `runsc` 的 environments 应与普通 OCI runtime environments 区分记录。

### `kata-runtime`

Kata Containers 通过将 workload 启动在 lightweight virtual machine 中，进一步推进了 boundary。就管理方式而言，它仍然可能看起来像是一个 container deployment，orchestration layers 也可能仍然将其视为 container，但底层 isolation boundary 更接近 virtualization，而不是经典的共享 host kernel 的 container。当希望在不放弃 container-centric workflows 的情况下获得更强的 tenant isolation 时，Kata 非常有用。

## Engines 与 Container Managers

如果说 low-level runtime 是直接与 kernel 通信的组件，那么 engine 或 manager 就是 users 和 operators 通常交互的组件。它负责 image pulls、metadata、logs、networks、volumes、lifecycle operations 以及 API exposure。这一层极其重要，因为许多现实中的 compromises 都发生在这里：即使 low-level runtime 本身完全正常，访问 runtime socket 或 daemon API 也可能等同于实现 host compromise。

### Docker Engine

Docker Engine 是 developers 最熟悉的 container platform，也是 container vocabulary 变得如此 Docker 化的原因之一。典型路径是 `docker` CLI 到 `dockerd`，后者再协调 `containerd` 和 OCI runtime 等 lower-level components。历史上，Docker deployments 通常是 **rootful** 的，因此访问 Docker socket 会成为非常强大的 primitive。这就是为什么大量实际的 privilege-escalation material 都关注 `docker.sock`：如果某个 process 能够请求 `dockerd` 创建 privileged container、挂载 host paths 或加入 host namespaces，那么它可能根本不需要 kernel exploit。

### Podman

Podman 的设计围绕更加 daemonless 的 model 展开。在 operation 层面，这有助于强化这样一种理念：containers 只是通过标准 Linux mechanisms 管理的 processes，而不是由一个长期运行的 privileged daemon 管理。与许多人最初接触的经典 Docker deployments 相比，Podman 也拥有更强的 **rootless** 能力。这并不意味着 Podman 自动安全，但它会显著改变默认 risk profile，尤其是在结合 user namespaces、SELinux 和 `crun` 时。

### containerd

containerd 是许多现代 stacks 中的核心 runtime management component。它被 Docker 使用，也是主要的 Kubernetes runtime backends 之一。它提供 powerful APIs，管理 images 和 snapshots，并将最终的 process creation 委托给 low-level runtime。关于 containerd 的 security discussions 应强调：访问 containerd socket 或 `ctr`/`nerdctl` functionality 可能与访问 Docker API 同样危险，即使其 interface 和 workflow 没有那么 "developer friendly"。

### CRI-O

CRI-O 的定位比 Docker Engine 更专一。它不是一个通用的 developer platform，而是围绕干净实现 Kubernetes Container Runtime Interface 构建的。因此，它在 Kubernetes distributions 以及 OpenShift 等大量使用 SELinux 的 ecosystems 中尤其常见。从 security 角度看，这种更狭窄的 scope 很有用，因为它减少了 conceptual clutter：CRI-O 非常明确地属于 "为 Kubernetes 运行 containers" 这一层，而不是一个全能 platform。

### Incus、LXD 与 LXC

Incus/LXD/LXC systems 应当与 Docker-style application containers 分开考虑，因为它们通常被用作 **system containers**。system container 通常需要表现得更像一个 lightweight machine，具有更完整的 userspace、长期运行的 services、更丰富的 device exposure 以及更广泛的 host integration。其 isolation mechanisms 仍然是 kernel primitives，但 operation expectations 不同。因此，这里的 misconfigurations 往往不像 "bad app-container defaults"，而更像 lightweight virtualization 或 host delegation 中的错误。

### systemd-nspawn

systemd-nspawn 处于一个有趣的位置，因为它是 systemd-native，并且非常适合 testing、debugging 以及运行 OS-like environments。它不是 cloud-native production runtime 的主流选择，但在 labs 和面向 distro 的 environments 中出现得足够频繁，因此值得一提。从 security analysis 的角度看，它再次提醒我们，"container" 这一概念横跨多个 ecosystems 和 operation styles。

### Apptainer / Singularity

Apptainer（以前称为 Singularity）在 research 和 HPC environments 中很常见。它的 trust assumptions、user workflow 和 execution model 与以 Docker/Kubernetes 为中心的 stacks 存在重要差异。特别是，这些 environments 通常非常重视让 users 运行 packaged workloads，同时不向他们授予广泛的 privileged container-management powers。如果 reviewer 假设每个 container environment 基本上都是 "server 上的 Docker"，就会严重误解这些 deployments。

## Build-Time Tooling

许多 security discussions 只讨论 run time，但 build-time tooling 同样重要，因为它决定 image contents、build secrets exposure，以及多少 trusted context 会被嵌入最终 artifact。

**BuildKit** 和 `docker buildx` 是现代 build backends，支持 caching、secret mounting、SSH forwarding 和 multi-platform builds 等 features。这些 features 很有用，但从 security 角度看，它们也会产生一些位置，使 secrets 可能 leak 到 image layers 中，或者使过于宽泛的 build context 暴露本不应被包含的 files。**Buildah** 在 OCI-native ecosystems 中承担类似角色，尤其是在 Podman 周边；而 **Kaniko** 则经常用于不希望向 build pipeline 授予 privileged Docker daemon 的 CI environments。

关键经验是，image creation 和 image execution 是两个不同的 phases，但 weak build pipeline 可能在 container 启动之前很久，就已经造成 weak runtime posture。

## Orchestration 是另一层，而不是 Runtime

不应在 mental model 中将 Kubernetes 等同于 runtime 本身。Kubernetes 是 orchestrator。它负责调度 Pods、存储 desired state，并通过 workload configuration 表达 security policy。随后，kubelet 与 CRI implementation（例如 containerd 或 CRI-O）通信，而后者再调用 low-level runtime，例如 `runc`、`crun`、`runsc` 或 `kata-runtime`。

这种分离很重要，因为许多人会错误地将某个 protection 归因于 "Kubernetes"，而实际上它是由 node runtime 强制执行的；或者将某种来自 Pod spec 的行为归咎于 "containerd defaults"。实际上，最终的 security posture 是多部分组合的结果：orchestrator 提出请求，runtime stack 对其进行转换，最后由 kernel 强制执行。

## 为什么 Assessment 期间识别 Runtime 很重要

如果尽早识别 engine 和 runtime，后续许多 observations 会更容易解释。rootless Podman container 表明 user namespaces 很可能是其中的一部分。挂载到 workload 中的 Docker socket 表明，基于 API 的 privilege escalation 可能是一条现实路径。CRI-O/OpenShift node 应立即让你想到 SELinux labels 和 restricted workload policy。gVisor 或 Kata environment 则应让你更加谨慎，不要假设经典的 `runc` breakout PoC 会表现相同。

因此，container assessment 的第一步之一应始终是回答两个简单问题：**哪个组件正在管理 container**，以及 **哪个 runtime 实际启动了该 process**。明确这两个答案后，通常就更容易理解整个 environment。

## Runtime Vulnerabilities

并非每次 container escape 都源于 operator misconfiguration。有时，runtime 本身就是 vulnerable component。这一点很重要，因为 workload 即使运行在看似谨慎的 configuration 下，也可能通过 low-level runtime flaw 暴露出来。

经典示例是 `runc` 中的 **CVE-2019-5736**：恶意 container 可以覆盖 host 上的 `runc` binary，然后等待后续的 `docker exec` 或类似 runtime invocation 触发 attacker-controlled code。该 exploit path 与简单的 bind-mount 或 capability mistake 差异很大，因为它利用了 runtime 在处理 exec 时重新进入 container process space 的方式。<sup>[[1]](#references)</sup>

从 red-team 角度看，一个最小 reproduction workflow 是：
```bash
go build main.go
./main
```
然后，从主机上：
```bash
docker exec -it <container-name> /bin/sh
```
关键要点并不是确切的历史 exploit 实现，而是其评估意义：如果 runtime 版本存在漏洞，那么即使可见的容器配置看起来并没有明显的弱点，普通的容器内代码执行也可能足以 compromise 主机。

近期 runtime CVE（例如 `runc` 中的 `CVE-2024-21626`、BuildKit mount race，以及 containerd parsing bug）进一步印证了这一点。runtime 版本和补丁级别属于 security boundary 的一部分，而不仅仅是维护琐事。

## References

- [1] [通过 runC 逃逸 Docker —— 解释 CVE-2019-5736](https://unit42.paloaltonetworks.com/breaking-docker-via-runc-explaining-cve-2019-5736/)
{{#include ../../../banners/hacktricks-training.md}}
