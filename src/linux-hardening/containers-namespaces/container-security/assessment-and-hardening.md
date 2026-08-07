# Assessment And Hardening

{{#include ../../../banners/hacktricks-training.md}}

## 概述

一次良好的 container assessment 应同时回答两个问题。第一，攻击者可以从当前 workload 中做什么？第二，哪些 operator 选择促成了这些可能性？Enumeration tools 有助于回答第一个问题，而 hardening 指南则有助于回答第二个问题。将两者放在同一页面上，可以让本节更适合作为现场参考，而不只是 escape 技巧目录。

现代环境中的一个实际变化是，许多较早的 container writeup 默默认假设使用的是 **rootful runtime**、**没有 user namespace isolation**，并且通常使用 **cgroup v1**。这些假设如今已不再安全。在花时间研究旧的 escape primitives 之前，应先确认 workload 是否为 rootless 或 userns-remapped、主机是否使用 cgroup v2，以及 Kubernetes 或 runtime 当前是否应用了默认的 seccomp 和 AppArmor profiles。这些细节通常决定某个著名 breakout 是否仍然适用。

## Enumeration Tools

以下工具仍然适合快速描述 container 环境：

- `linpeas` 可以识别许多 container indicators、mounted sockets、capability sets、dangerous filesystems 以及 breakout hints。
- `CDK` 专门面向 container 环境，包含 enumeration 和一些自动化 escape checks。
- `amicontained` 轻量且实用，可用于识别 container restrictions、capabilities、namespace exposure 以及可能的 breakout classes。
- `deepce` 是另一个面向 container 的 enumerator，包含以 breakout 为导向的 checks。
- `grype` 适合在 assessment 包含 image-package vulnerability review，而不仅是 runtime escape analysis 时使用。
- `Tracee` 适合在需要 **runtime evidence** 而不只是静态 posture 时使用，尤其适用于收集可疑的 process execution、file access 以及与 container 相关的 events。
- `Inspektor Gadget` 适合 Kubernetes 和 Linux-host investigations，能够在需要时提供由 eBPF 支持的可见性，并将信息关联回 pods、containers、namespaces 以及其他更高层概念。

这些工具的价值在于速度和覆盖范围，而不是确定性。它们有助于快速了解整体 posture，但有价值的发现仍需要结合实际的 runtime、namespace、capability 和 mount model 进行人工解读。

## Hardening 优先级

最重要的 hardening 原则在概念上很简单，尽管其实现方式会因平台而异。避免使用 privileged containers。避免挂载 runtime sockets。除非有非常明确的理由，否则不要为 containers 提供可写的 host paths。在可行的情况下使用 user namespaces 或 rootless execution。删除所有 capabilities，仅重新添加 workload 确实需要的 capabilities。保持 seccomp、AppArmor 和 SELinux 启用，不要为了修复 application compatibility 问题而禁用它们。限制资源，以便被 compromise 的 container 无法轻易对 host 实施 denial of service。

Image 和 build hygiene 与 runtime posture 同样重要。使用 minimal images，频繁 rebuild，进行 scanning，在实际可行时要求 provenance，并将 secrets 排除在 layers 之外。以 non-root 身份运行、使用较小 image、并具有有限 syscall 和 capability surface 的 container，比使用大型 convenience image、以等同于 host root 的权限运行、且预装 debugging tools 的 container 更容易防御。

对于 Kubernetes，当前的 hardening baselines 比许多 operator 仍认为的更加严格。内置的 **Pod Security Standards** 将 `restricted` 视为“current best practice” profile：`allowPrivilegeEscalation` 应为 `false`，workloads 应以 non-root 身份运行，seccomp 应明确设置为 `RuntimeDefault` 或 `Localhost`，并且 capability sets 应积极删除。在 assessment 期间，这一点很重要，因为只使用 `warn` 或 `audit` labels 的 cluster 可能在纸面上看起来已经 hardened，但实际上仍会接受存在风险的 pods。<sup>[[1]](#references)</sup>

## Modern Triage Questions

在深入研究特定于 escape 的页面之前，先回答以下快速问题：

1. 该 workload 是 **rootful**、**rootless** 还是 **userns-remapped**？
2. 该 node 使用的是 **cgroup v1** 还是 **cgroup v2**？
3. **seccomp** 和 **AppArmor/SELinux** 是显式配置的，还是仅在可用时继承？
4. 在 Kubernetes 中，该 namespace 实际上是在 **enforcing** `baseline` 或 `restricted`，还是仅进行 warning/auditing？

Useful checks:
```bash
id
cat /proc/self/uid_map 2>/dev/null
cat /proc/self/gid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/1/attr/current 2>/dev/null
find /var/run/secrets -maxdepth 3 -type f 2>/dev/null | head
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get ns "$NS" -o jsonpath='{.metadata.labels}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.supplementalGroupsPolicy}{"\n"}' 2>/dev/null
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.securityContext.seccompProfile.type}{"\n"}{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.capabilities.drop}{"\n"}' 2>/dev/null
```
这里值得关注的是：

- 如果 `/proc/self/uid_map` 显示 container root 映射到 **高位 host UID 范围**，许多较早的 host-root writeup 就不再那么适用，因为 container 中的 root 已不再等同于 host-root。
- 如果 `/sys/fs/cgroup` 是 `cgroup2fs`，那么诸如 `release_agent` abuse 之类的旧 **cgroup v1** 专用 writeup 不应再作为首要猜测。
- 如果 seccomp 和 AppArmor 仅以隐式方式继承，其可移植性可能弱于 defenders 的预期。在 Kubernetes 中，显式设置 `RuntimeDefault` 通常比默默依赖 node defaults 更安全。
- 如果 `supplementalGroupsPolicy` 设置为 `Strict`，pod 应避免从镜像内的 `/etc/group` 中静默继承额外的 group memberships，从而使基于 group 的 volume 和 file access 行为更加可预测。
- 值得直接检查 namespace labels，例如 `pod-security.kubernetes.io/enforce=restricted`。`warn` 和 `audit` 很有用，但不会阻止创建存在风险的 pod。

## Runtime Baseline Triage

runtime baseline 是一次快速检查，用于判断 container 看起来是普通的隔离 workload，还是可能影响 host 的 control plane foothold。它应收集足够的信息，以便确定下一步优先查看的内容：runtime socket abuse、host mounts、namespaces、cgroups、capabilities，或 image-secret review。

从 workload 内部执行的实用检查：
```bash
id
hostname
cat /proc/1/cgroup 2>/dev/null
cat /proc/self/uid_map 2>/dev/null
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
stat -fc %T /sys/fs/cgroup 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
readlink /proc/self/ns/{pid,mnt,net,ipc,cgroup,user} 2>/dev/null
mount
find /run /var/run -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
解读：

- 即使没有干净的逃逸路径，缺失或不受限制的 `memory.max` / `pids.max` 也表明 blast radius 控制较弱。
- 与范围受限的 non-root workload 相比，具有 `NoNewPrivs: 0`、广泛 capabilities 以及宽松 seccomp 配置的 root shell 更值得关注。
- Runtime sockets 和可写的 host mounts 通常比 kernel exploits 优先级更高，因为它们已经暴露了管理或文件系统控制路径。
- 共享的 PID、network、IPC 或 cgroup namespaces 本身并不总能直接实现完全逃逸，但会让下一步更容易被发现。

## Resource-Exhaustion Examples

Resource controls 并不引人注目，但它们是 container security 的一部分，因为可以限制 compromise 的 blast radius。没有 memory、CPU 或 PID 限制时，一个简单的 shell 就可能足以降低 host 或相邻 workloads 的性能。

影响 host 的测试示例：
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
这些示例很有用，因为它们表明，并非每一种危险的 container 结果都是一次干净利落的“escape”。薄弱的 cgroup 限制仍然可能将 code execution 转化为真实的运营影响。

在基于 Kubernetes 的环境中，在认为 DoS 只是理论问题之前，还应检查是否实际存在资源控制：
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## Hardening Tooling

对于以 Docker 为中心的环境，`docker-bench-security` 仍然是一个有用的主机侧审计基线，因为它会依据广泛认可的基准指南检查常见的配置问题：
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
该工具不能替代 threat modeling，但对于发现随着时间推移而累积的粗心 daemon、mount、network 和 runtime 默认配置，仍然很有价值。

对于 Kubernetes 和高度依赖 runtime 的环境，应将静态检查与 runtime 可见性结合起来：

- `Tracee` 适用于面向容器的 runtime 检测，以及在需要确认遭入侵 workload 实际访问过哪些内容时进行快速取证。
- `Inspektor Gadget` 适用于需要将 kernel 级 telemetry 映射回 pods、containers、DNS 活动、文件执行或 network 行为的 assessment。

## 检查

在 assessment 期间，将以下命令作为快速的初步检查：
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
这里有哪些值得关注的内容：

- 具有广泛 capabilities 且 `Seccomp: 0` 的 root process 值得立即关注。
- 同时具有 **1:1 UID map** 的 root process，远比处于正确隔离的 user namespace 中的“root”更值得关注。
- `cgroup2fs` 通常意味着许多旧的 **cgroup v1** escape chains 并不是最佳起点，而缺少 `memory.max` 或 `pids.max` 仍然表明 blast radius 控制较弱。
- 可疑的 mounts 和 runtime sockets 通常比任何 kernel exploit 都能更快造成影响。
- 弱 runtime posture 与弱 resource limits 的组合，通常表明这是一个整体上较为宽松的 container environment，而不是某个单独的隔离配置错误。

## References

- [1] [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)

{{#include ../../../banners/hacktricks-training.md}}
