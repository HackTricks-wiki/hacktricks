# Container Runtimes、Engines、Builders 和 Sandboxes

{{#include ../../../banners/hacktricks-training.md}}

Container security 中最大的困惑来源之一，是多个完全不同的组件经常被统称为同一个词。“Docker”可能指 image format、CLI、daemon、build system、runtime stack，或者泛指 containers。对于安全工作来说，这种歧义会造成问题，因为不同层负责不同的防护。由错误 bind mount 导致的 breakout，与由 low-level runtime bug 导致的 breakout 并不是一回事；二者也都不同于 Kubernetes 中的 cluster policy 配置错误。

本页面按角色划分整个生态，以便本节后续内容能够准确讨论某项防护或弱点究竟存在于哪一层。

## OCI 作为通用语言

现代 Linux container stacks 通常可以互操作，因为它们使用一组 OCI specifications。**OCI Image Specification** 描述 image 和 layer 的表示方式。**OCI Runtime Specification** 描述 runtime 应如何启动进程，包括 namespaces、mounts、cgroups 和 security settings。**OCI Distribution Specification** 则标准化 registries 暴露内容的方式。

这很重要，因为它解释了为什么使用某个 tool 构建的 container image 通常可以使用另一个 tool 运行，也解释了为什么多个 engines 可以共享同一个 low-level runtime。它还解释了为什么不同产品的 security behavior 看起来相似：其中许多产品都在构造相同的 OCI runtime configuration，并将其交给同一小组 runtimes。

## Low-Level OCI Runtimes

Low-level runtime 是最接近 kernel boundary 的组件。它负责实际创建 namespaces、写入 cgroup settings、应用 capabilities 和 seccomp filters，最后对 container process 执行 `execve()`。当人们从机械层面讨论 “container isolation” 时，通常指的就是这一层，即使他们没有明确这样说。

### `runc`

`runc` 是 reference OCI runtime，仍然是最知名的实现。它广泛用于 Docker、containerd 以及许多 Kubernetes deployments 中。大量公开 research 和 exploitation material 都针对 `runc`-style environments，这只是因为它们很常见，也因为 `runc` 定义了许多人想象 Linux container 时所依据的 baseline。理解 `runc` 因此能够为 classic container isolation 提供强有力的 mental model。

### `crun`

`crun` 是另一个 OCI runtime，使用 C 编写，并广泛用于现代 Podman environments。它通常因良好的 cgroup v2 support、出色的 rootless ergonomics 以及较低的 overhead 而受到认可。从安全角度看，重要的并不是它使用了另一种 language 编写，而是它仍然承担相同的角色：将 OCI configuration 转换为 kernel 下运行的 process tree。Rootless Podman workflow 通常感觉更安全，并不是因为 `crun` 能神奇地解决所有问题，而是因为其周围的整体 stack 往往更强调 user namespaces 和 least privilege。

### 来自 gVisor 的 `runsc`

`runsc` 是 gVisor 使用的 runtime。在这里，boundary 的含义发生了实质变化。gVisor 并不是像通常方式那样将大多数 syscalls 直接传递给 host kernel，而是插入一个 userspace kernel layer，对 Linux interface 的大部分内容进行 emulation 或 mediation。其结果不是一个只增加了几个 flags 的普通 `runc` container，而是一种不同的 sandbox design，目的是减少 host-kernel attack surface。Compatibility 和 performance tradeoffs 是该设计的一部分，因此使用 `runsc` 的 environments 应当与普通 OCI runtime environments 分开记录。

### `kata-runtime`

Kata Containers 通过将 workload 启动在 lightweight virtual machine 中，进一步推进了 isolation boundary。从管理角度看，这仍然可能像是一次 container deployment，orchestration layers 也可能仍将其作为 container 处理，但底层 isolation boundary 更接近 virtualization，而不是 classic host-kernel-shared container。当希望获得更强的 tenant isolation，同时又不放弃 container-centric workflows 时，Kata 非常有用。

## Engines 和 Container Managers

如果说 low-level runtime 是直接与 kernel 通信的组件，那么 engine 或 manager 就是 users 和 operators 通常交互的组件。它负责 image pulls、metadata、logs、networks、volumes、lifecycle operations 以及 API exposure。这一层极其重要，因为许多现实世界中的 compromises 都发生在这里：即使 low-level runtime 本身完全正常，访问 runtime socket 或 daemon API 也可能等同于 host compromise。

### Docker Engine

Docker Engine 是开发者最熟悉的 container platform，也是 container vocabulary 变得如此 Docker 化的原因之一。典型路径是 `docker` CLI 到 `dockerd`，后者再协调 `containerd` 和 OCI runtime 等 lower-level components。历史上，Docker deployments 通常是 **rootful** 的，因此访问 Docker socket 会成为非常强大的 primitive。这就是为什么大量实际 privilege-escalation material 都聚焦于 `docker.sock`：如果某个 process 能够请求 `dockerd` 创建 privileged container、挂载 host paths 或加入 host namespaces，那么它可能完全不需要 kernel exploit。

### Podman

Podman 围绕更偏向 daemonless 的 model 设计。在操作层面，这有助于强化这样一种理念：containers 只是通过标准 Linux mechanisms 管理的 processes，而不是由一个长期运行的 privileged daemon 管理。与许多人最初接触的 classic Docker deployments 相比，Podman 也拥有更强的 **rootless** 支持。这并不意味着 Podman 自动安全，但它会显著改变默认 risk profile，尤其是在结合 user namespaces、SELinux 和 `crun` 时。

### containerd

containerd 是许多现代 stacks 中的核心 runtime management component。它被 Docker 使用，也是主要的 Kubernetes runtime backends 之一。它暴露 powerful APIs，管理 images 和 snapshots，并将最终的 process creation 委托给 low-level runtime。关于 containerd 的安全讨论应当强调：访问 containerd socket 或 `ctr`/`nerdctl` functionality 可能与访问 Docker API 一样危险，即使其 interface 和 workflow 感觉不那么 “developer friendly”。

### CRI-O

CRI-O 的定位比 Docker Engine 更明确。它不是通用的 developer platform，而是围绕干净实现 Kubernetes Container Runtime Interface 构建的。因此，它在 Kubernetes distributions 以及 OpenShift 等 heavily 使用 SELinux 的 ecosystems 中尤其常见。从安全角度看，这种更窄的 scope 很有用，因为它减少了 conceptual clutter：CRI-O 明确属于 “为 Kubernetes 运行 containers” 这一层，而不是一个包罗万象的平台。

### Incus、LXD 和 LXC

Incus/LXD/LXC systems 应当与 Docker-style application containers 分开，因为它们经常被用作 **system containers**。System container 通常应当更像一个 lightweight machine，拥有更完整的 userspace、长期运行的 services、更丰富的 device exposure 以及更广泛的 host integration。其 isolation mechanisms 仍然是 kernel primitives，但 operational expectations 不同。因此，这里的 misconfigurations 通常不像 “bad app-container defaults”，而更像 lightweight virtualization 或 host delegation 中的错误。

### systemd-nspawn

systemd-nspawn 位于一个有趣的位置，因为它是 systemd-native，并且非常适合 testing、debugging 以及运行类似 OS 的 environments。它不是 cloud-native production runtime 的主流选择，但在 labs 和面向 distro 的 environments 中出现得足够频繁，因此值得一提。在 security analysis 中，它再次提醒我们：“container” 这一概念横跨多个 ecosystems 和 operational styles。

### Apptainer / Singularity

Apptainer（原名 Singularity）在 research 和 HPC environments 中很常见。它的 trust assumptions、user workflow 以及 execution model，与以 Docker/Kubernetes 为中心的 stacks 存在重要差异。尤其是，这些 environments 通常非常重视让 users 运行 packaged workloads，同时不赋予他们广泛的 privileged container-management powers。如果 reviewer 假定每个 container environment 基本都是 “server 上的 Docker”，就会严重误解这些 deployments。

## Build-Time Tooling

许多 security discussions 只讨论 run time，但 build-time tooling 同样重要，因为它决定 image contents、build secrets exposure，以及最终 artifact 中嵌入多少 trusted context。

**BuildKit** 和 `docker buildx` 是现代 build backends，支持 caching、secret mounting、SSH forwarding 以及 multi-platform builds 等 features。这些都是有用的 features，但从安全角度看，它们也会带来一些位置，使 secrets 可能 leak 到 image layers 中，或者使过于宽泛的 build context 暴露本不应被包含的 files。**Buildah** 在 OCI-native ecosystems 中承担类似角色，尤其是在 Podman 周边；而 **Kaniko** 经常用于不希望向 build pipeline 授予 privileged Docker daemon 的 CI environments。

关键结论是，image creation 和 image execution 是不同的 phases，但 weak build pipeline 可能早在 container 启动之前，就已经造成 weak runtime posture。

## Orchestration 是另一层，而不是 Runtime

不应在思维上将 Kubernetes 等同于 runtime 本身。Kubernetes 是 orchestrator。它负责调度 Pods、存储 desired state，并通过 workload configuration 表达 security policy。随后 kubelet 与 CRI implementation（例如 containerd 或 CRI-O）通信，而后者再调用 `runc`、`crun`、`runsc` 或 `kata-runtime` 等 low-level runtime。

这种分离很重要，因为许多人会错误地将某项 protection 归因于 “Kubernetes”，而实际上它是由 node runtime 强制执行的；或者他们将某种行为归咎于 “containerd defaults”，但该行为实际上来自 Pod spec。实践中，最终的 security posture 是多个部分的组合：orchestrator 发出请求，runtime stack 对其进行转换，最后由 kernel 强制执行。

## 为什么在 Assessment 期间识别 Runtime 很重要

如果尽早识别 engine 和 runtime，之后的许多 observations 会更容易解释。Rootless Podman container 表明 user namespaces 可能是其中的一部分。挂载到 workload 中的 Docker socket 表明，基于 API 的 privilege escalation 是一条现实路径。CRI-O/OpenShift node 应当立即让你想到 SELinux labels 和 restricted workload policy。gVisor 或 Kata environment 则应当让你更加谨慎，不要假设 classic `runc` breakout PoC 会表现得完全相同。

因此，container assessment 的第一步之一始终应当是回答两个简单问题：**哪个组件正在管理该 container**，以及 **实际启动该 process 的 runtime 是什么**。一旦明确了这些答案，通常就会更容易分析环境的其余部分。

## Runtime Vulnerabilities

并非每次 container escape 都源于 operator misconfiguration。有时 runtime 本身就是 vulnerable component。这一点很重要，因为 workload 即使使用了看似谨慎的 configuration，仍然可能通过 low-level runtime flaw 暴露出来。

经典示例是 `runc` 中的 **CVE-2019-5736**：malicious container 可以覆盖 host 上的 `runc` binary，然后等待后续的 `docker exec` 或类似 runtime invocation 触发 attacker-controlled code。该 exploit path 与简单的 bind-mount 或 capability mistake 完全不同，因为它利用了 runtime 在 exec handling 期间重新进入 container process space 的方式。

从 red-team 角度看，一个 minimal reproduction workflow 是：
```bash
go build main.go
./main
```
然后，在 host 上：
```bash
docker exec -it <container-name> /bin/sh
```
关键教训并不在于确切的历史 exploit 实现，而在于评估层面的影响：如果 runtime 版本存在漏洞，那么即使可见的容器配置并没有明显的弱点，普通的容器内代码执行也可能足以 compromise 主机。

近期 runtime CVE（例如 `runc` 中的 `CVE-2024-21626`、BuildKit mount race，以及 containerd parsing bug）进一步印证了这一点。runtime 版本和 patch level 都属于 security boundary 的一部分，而不仅仅是维护方面的琐事。
{{#include ../../../banners/hacktricks-training.md}}
