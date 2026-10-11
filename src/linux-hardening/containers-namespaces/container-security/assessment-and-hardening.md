# 评估与加固

{{#include ../../../banners/hacktricks-training.md}}

## 概述

良好的容器评估应回答两个并行的问题。首先，攻击者能从当前工作负载中做什么？其次，哪些运维人员的选择导致了这种情况？枚举工具有助于回答第一个问题，加固指南则有助于回答第二个问题。将两者放在同一页上，能让本节成为更实用的现场参考，而不只是逃逸技巧目录。

现代环境中一个实际需要更新的认识是，许多较旧的容器文章默认使用 **rootful runtime**、**没有 user namespace 隔离**，而且通常采用 **cgroup v1**。这些假设如今已不再可靠。在花时间研究旧的逃逸原语之前，先确认工作负载是否为 rootless 或 userns-remapped、主机是否使用 cgroup v2，以及 Kubernetes 或 runtime 是否已应用默认的 seccomp 和 AppArmor 配置文件。这些细节往往决定某种著名的逃逸方法是否仍然适用。

## 枚举工具

有不少工具仍适合用于快速了解容器环境：

- `linpeas` 可识别许多容器迹象、挂载的 socket、capability 集、危险文件系统以及逃逸线索。
- `CDK` 专门针对容器环境，包含枚举功能和一些自动化逃逸检查。
- `amicontained` 轻量实用，可用于识别容器限制、capability、namespace 暴露情况以及可能的逃逸类别。
- `deepce` 是另一款面向容器的枚举工具，包含以逃逸为重点的检查。
- `grype` 适用于评估中包含镜像软件包漏洞审查，而不仅是运行时逃逸分析的情况。
- `Tracee` 适用于需要**运行时证据**而不只是静态安全状况的场景，尤其是要收集可疑进程执行、文件访问以及具备容器上下文的事件时。
- `Inspektor Gadget` 适用于 Kubernetes 和 Linux 主机调查，可提供 eBPF 支持的可视化信息，并将其关联到 Pod、容器、namespace 等更高层级的概念。

这些工具的价值在于速度和覆盖范围，而非绝对可靠。它们有助于快速了解大致安全状况，但仍需结合实际的 runtime、namespace、capability 和挂载模型，对有价值的发现进行人工分析。

## 加固优先事项

最重要的加固原则在概念上很简单，但具体实施方式因平台而异。避免使用 privileged 容器。避免挂载 runtime socket。除非有非常明确的理由，否则不要为容器提供可写的主机路径。在可行时使用 user namespace 或 rootless 执行。移除所有 capability，只添加工作负载真正需要的 capability。保持 seccomp、AppArmor 和 SELinux 启用，不要为了修复应用兼容性问题而将其关闭。限制资源，避免被攻陷的容器轻易对主机造成拒绝服务。

镜像和构建卫生与运行时安全状况同样重要。使用精简镜像，频繁重新构建并扫描镜像，在可行时要求提供来源证明，并避免将密钥放入镜像层。与使用大型便利镜像、以等同于主机 root 的权限运行且预装调试工具相比，运行于非 root 用户、使用精简镜像并具有有限 syscall 和 capability 攻击面的容器更容易防御。

对于 Kubernetes，当前的加固基线比许多运维人员仍认为的更为严格。内置的 **Pod Security Standards** 将 `restricted` 视为“当前最佳实践”配置文件：`allowPrivilegeEscalation` 应为 `false`，工作负载应以非 root 用户运行，seccomp 应明确设为 `RuntimeDefault` 或 `Localhost`，并应积极移除 capability。在评估期间，这一点很重要：集群如果只使用 `warn` 或 `audit` 标签，纸面上看似已加固，实际仍可能允许有风险的 Pod。<sup>[[1]](#references)</sup>

如果 Pod 挂载了 service-account token，请**针对每个目标 namespace**评估其权限。某条规则允许列出一个 namespace 中的 Pod，并不能证明其在另一个 namespace 中也有权限；挂载在另一个 Pod 中的 token 也可能拥有不同权限。请使用正在审查的实际身份运行 `kubectl auth can-i list pods -n <target-namespace>` 和 `kubectl auth can-i list secrets -n <target-namespace>`。允许列出 Secret 是一条重要线索，因为列表响应可能包含 Secret 内容，但这并不能证明其中存在具有特权的 token。要访问主机，还需要具备可用的工作负载创建权限、准入策略允许所提议的 `hostPath` 挂载，以及节点/Pod 安全上下文允许执行预期的文件操作。请参阅 Kubernetes 的[授权检查](https://kubernetes.io/docs/reference/access-authn-authz/authorization/)和 [RBAC 权限提升指南](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)。

## 现代化分诊问题

在深入阅读特定逃逸方法的页面之前，先快速回答以下问题：

1. 工作负载是 **rootful**、**rootless** 还是 **userns-remapped**？
2. 节点使用的是 **cgroup v1** 还是 **cgroup v2**？
3. 是否明确配置了 **seccomp** 和 **AppArmor/SELinux**，还是仅在可用时继承配置？
4. 在 Kubernetes 中，namespace 是否实际在**强制执行** `baseline` 或 `restricted`，还是只发出警告/进行审计？

有用的检查：

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

这里有哪些值得关注的地方：

- 如果 `/proc/self/uid_map` 显示容器 root 映射到**较高的 host UID 范围**，许多旧的 host-root writeup 就不那么适用了，因为容器中的 root 已不再等同于 host-root。
- 如果 `/sys/fs/cgroup` 是 `cgroup2fs`，那么旧的、针对 **cgroup v1** 的 writeup（例如滥用 `release_agent`）就不该再是你的首选思路。
- 如果 seccomp 和 AppArmor 只是隐式继承的，其可移植性可能比防御者预期的更弱。在 Kubernetes 中，显式设置 `RuntimeDefault` 通常比默默依赖节点默认值更可靠。
- 如果 `supplementalGroupsPolicy` 设置为 `Strict`，Pod 应避免从镜像中的 `/etc/group` 静默继承额外的组成员身份，从而让基于组的卷和文件访问行为更可预测。
- 值得直接检查命名空间标签，例如 `pod-security.kubernetes.io/enforce=restricted`。`warn` 和 `audit` 虽然有用，但无法阻止创建存在风险的 Pod。

## 运行时基线初步排查

运行时基线是一次快速检查，用于判断容器看起来是普通的隔离工作负载，还是可能影响 host 的控制平面立足点。检查应收集足够的信息，以便确定接下来优先阅读的内容：运行时 socket 滥用、host 挂载、命名空间、cgroups、capabilities，或镜像密钥审查。

在工作负载内部可执行的实用检查：

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

- 缺少 `memory.max` / `pids.max` 限制或限制为 unlimited，说明爆炸半径控制较弱，即使没有明确的逃逸漏洞也是如此。
- 与受限的非 root workload 相比，拥有 `NoNewPrivs: 0`、广泛 capabilities 和宽松 seccomp 的 root shell 更值得关注。
- Runtime sockets 和可写的 host mounts 通常比 kernel exploits 更值得优先关注，因为它们已经提供了管理或文件系统控制路径。
- 共享 PID、network、IPC 或 cgroup namespaces 本身不一定构成完整逃逸，但会让后续步骤更容易被发现。

## 资源耗尽示例

资源限制并不引人注目，但它们是容器安全的一部分，因为它们能限制 compromise 的爆炸半径。没有 memory、CPU 或 PID 限制时，一个简单的 shell 就可能足以降低 host 或相邻 workloads 的性能。

对 host 造成影响的测试示例：

```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```

这些示例很有用，因为它们表明，并非每种危险的 container 后果都会造成彻底的“escape”。薄弱的 cgroup 限制仍可能让代码执行造成实际的运营影响。

在 Kubernetes 支持的环境中，在将 DoS 视为理论风险之前，也要检查是否存在资源控制：

```bash
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{range .spec.containers[*]}{.name}{" cpu="}{.resources.limits.cpu}{" mem="}{.resources.limits.memory}{"\n"}{end}' 2>/dev/null
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```

## 加固工具

对于以 Docker 为中心的环境，`docker-bench-security` 仍是有用的主机端审计基线，因为它会依据广泛认可的基准指南检查常见配置问题。应单独审查运行时安全公告，因为配置基准无法检测已安装的运行时是否受到新披露漏洞的影响。 <sup>[[2]](#references)</sup>

```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```

该工具不能替代威胁建模，但仍有助于发现长期累积的不谨慎 daemon、mount、network 和 runtime 默认配置。

对于 Kubernetes 和 runtime 密集型环境，应将静态检查与 runtime 可见性结合起来：

- `Tracee` 适用于支持容器感知的 runtime 检测和快速取证，帮助你确认受感染的工作负载实际接触过哪些内容。
- `Inspektor Gadget` 适用于需要将内核级遥测数据关联到 pod、容器、DNS 活动、文件执行或网络行为的评估。

## 检查

评估期间可使用以下命令进行快速初步检查：

```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map 2>/dev/null
stat -fc %T /sys/fs/cgroup 2>/dev/null
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```

这里有哪些值得关注的地方：

- 拥有广泛 capabilities 且 `Seccomp: 0` 的 root 进程值得立即关注。
- 同时具有 **1:1 UID 映射**的 root 进程，比在隔离完善的 user namespace 中的“root”更值得关注。
- `cgroup2fs` 通常意味着许多较旧的 **cgroup v1** 逃逸链不是最佳切入点；但缺少 `memory.max` 或 `pids.max` 仍表明影响范围控制较弱。
- 可疑挂载和 runtime socket 通常比任何内核漏洞利用更快造成影响。
- runtime 安全状况较弱且资源限制不足，通常说明容器环境整体过于宽松，而非单一孤立错误。

## References

- [1] [Kubernetes Pod 安全标准](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [2] [Docker 安全公告：runc、BuildKit 和 Moby 中的多个漏洞](https://docs.docker.com/security/security-announcements/)
{{#include ../../../banners/hacktricks-training.md}}
