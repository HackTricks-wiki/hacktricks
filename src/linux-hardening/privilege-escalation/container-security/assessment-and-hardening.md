# 评估与加固

{{#include ../../../banners/hacktricks-training.md}}

## 概览

一个好的 container assessment 应该回答两个并行问题。第一，攻击者能从当前 workload 做什么？第二，是哪些 operator 选择使之成为可能？Enumeration tools 有助于回答第一个问题，而 hardening guidance 有助于回答第二个问题。把两者放在同一页，会让这一节更像现场参考，而不只是逃逸技巧目录。

对于现代环境，一个实用的更新是：许多较旧的 container writeups 会默认假设 **rootful runtime**、**no user namespace isolation**，而且通常是 **cgroup v1**。这些假设现在已经不安全了。在花时间研究旧的 escape primitives 之前，先确认 workload 是否是 rootless 或 userns-remapped，主机是否使用 cgroup v2，以及 Kubernetes 或 runtime 是否正在应用默认的 seccomp 和 AppArmor profiles。这些细节往往决定了一个著名的 breakout 是否仍然适用。

## Enumeration Tools

一些工具仍然非常适合快速刻画 container 环境：

- `linpeas` 可以识别许多 container indicators、已挂载的 sockets、capability sets、危险文件系统和 breakout 提示。
- `CDK` 专注于 container 环境，包含 enumeration 以及一些自动化 escape checks。
- `amicontained` 轻量且适合识别 container 限制、capabilities、namespace 暴露情况，以及可能的 breakout 类别。
- `deepce` 是另一个面向 container 的 enumerator，带有 breakout-oriented checks。
- `grype` 在评估包含 image-package vulnerability review 而不只是 runtime escape analysis 时很有用。
- `Tracee` 在你需要 **runtime evidence** 而不是仅仅静态姿态时很有用，尤其适合可疑进程执行、文件访问以及 container-aware 事件收集。
- `Inspektor Gadget` 在 Kubernetes 和 Linux-host 调查中很有用，当你需要由 eBPF 提供支持的可见性，并将其关联回 pods、containers、namespaces 和其他更高层概念时。

这些工具的价值在于速度和覆盖面，而不是确定性。它们能快速暴露大致 posture，但有意思的发现仍需要结合实际 runtime、namespace、capability 和 mount model 进行手动解释。

## Hardening Priorities

最重要的 hardening 原则在概念上很简单，尽管不同平台上的实现方式各不相同。避免 privileged containers。避免挂载 runtime sockets。除非有非常明确的理由，不要给 containers 可写的 host paths。尽可能使用 user namespaces 或 rootless 执行。移除所有 capabilities，只加回 workload 真正需要的那些。保留 seccomp、AppArmor 和 SELinux 启用状态，而不是为了修复应用兼容性问题就把它们关闭。限制资源，这样被攻陷的 container 就不能轻易对主机发起 denial of service。

image 和 build hygiene 与 runtime posture 一样重要。使用最小化 images，频繁重建，扫描它们，在可行时要求 provenance，并且不要把 secrets 放进 layers。一个以 non-root 运行、image 体积小、syscall 和 capability surface 很窄的 container，比一个以 host-equivalent root 运行且预装调试工具的大型便利 image 更容易防御。

对于 Kubernetes，当前的 hardening baseline 比许多 operator 仍然假设的更有主见。内置的 **Pod Security Standards** 将 `restricted` 视为“当前最佳实践” profile：`allowPrivilegeEscalation` 应该为 `false`，workloads 应该以 non-root 运行，seccomp 应该显式设置为 `RuntimeDefault` 或 `Localhost`，并且 capability sets 应该积极地被 drop。在 assessment 期间，这一点很重要，因为一个只使用 `warn` 或 `audit` labels 的 cluster 在文档上看起来可能很安全，但实际仍可能放行 risky pods。

## Modern Triage Questions

在深入查看 escape-specific pages 之前，先回答这些快速问题：

1. workload 是 **rootful**、**rootless** 还是 **userns-remapped**？
2. 节点使用的是 **cgroup v1** 还是 **cgroup v2**？
3. **seccomp** 和 **AppArmor/SELinux** 是显式配置的，还是仅在可用时继承？
4. 在 Kubernetes 中，namespace 是否 वास्तवously 强制执行 `baseline` 或 `restricted`，还是只是在 warning/auditing？

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
这里有一些有趣的点：

- 如果 `/proc/self/uid_map` 显示 container root 映射到一个**较高的 host UID 范围**，那么许多旧的 host-root writeups 就不再那么相关，因为 container 里的 root 不再等同于 host-root。
- 如果 `/sys/fs/cgroup` 是 `cgroup2fs`，那么旧的、针对 **cgroup v1** 的 writeups，例如 `release_agent` abuse，就不应再作为你的首选猜测。
- 如果 seccomp 和 AppArmor 只是隐式继承，那么其可移植性可能比防御者预期的更弱。在 Kubernetes 中，显式设置 `RuntimeDefault` 往往比静默依赖 node 默认值更强。
- 如果 `supplementalGroupsPolicy` 被设置为 `Strict`，pod 应该避免静默继承 image 内 `/etc/group` 中的额外 group memberships，这会让基于 group 的 volume 和文件访问行为更可预测。
- 像 `pod-security.kubernetes.io/enforce=restricted` 这样的 namespace labels 值得直接检查。`warn` 和 `audit` 很有用，但它们并不会阻止一个有风险的 pod 被创建。

## Resource-Exhaustion Examples

Resource controls 并不炫酷，但它们是 container security 的一部分，因为它们限制了 compromise 的 blast radius。没有 memory、CPU 或 PID limits，一个简单的 shell 就足以拖慢 host 或相邻 workloads。

示例 host 影响测试：
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
这些示例很有用，因为它们表明，并非每一种危险的 container 结果都是干净的 "escape"。薄弱的 cgroup 限制仍然可以把 code execution 变成真正的 operational impact。

在 Kubernetes-backed 环境中，在把 DoS 视为理论问题之前，也要检查是否根本存在 resource controls：
```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## 加固工具

对于以 Docker 为中心的环境，`docker-bench-security` 仍然是一个有用的主机侧审计基线，因为它会根据广泛认可的基准指导检查常见的配置问题：
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
该工具不能替代 threat modeling，但它仍然很有价值，可以发现随着时间累积而出现的粗心 daemon、mount、network 和 runtime 默认配置。

对于 Kubernetes 和 runtime-heavy 环境，将静态检查与 runtime 可见性结合使用：

- `Tracee` 适用于 container-aware 的 runtime 检测，以及当你需要确认一个被 compromise 的 workload 实际访问了什么时，用于快速取证。
- `Inspektor Gadget` 适用于需要将 kernel-level telemetry 映射回 pods、containers、DNS activity、文件执行或 network 行为的 assessment。

## Checks

在 assessment 过程中，将这些作为快速的首轮命令使用：
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
这里值得注意的是：

- 一个拥有广泛 capabilities 且 `Seccomp: 0` 的 root 进程需要立即关注。
- 一个同时具有 **1:1 UID map** 的 root 进程，比“root” 仅存在于正确隔离的 user namespace 中要有趣得多。
- `cgroup2fs` 通常意味着许多较旧的 **cgroup v1** escape chains 不是你最好的起点，而缺少 `memory.max` 或 `pids.max` 仍然表明 blast-radius 控制很弱。
- 可疑的 mounts 和 runtime sockets 往往比任何 kernel exploit 都能更快地带来实际影响。
- 弱 runtime posture 与弱资源限制的组合，通常表明这是一个整体上较为宽松的 container 环境，而不是单个孤立的失误。

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Docker Security Advisory: Multiple Vulnerabilities in runc, BuildKit, and Moby](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
