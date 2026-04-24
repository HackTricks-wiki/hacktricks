# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` 是一个 kernel hardening feature，用于防止 process 在 `execve()` 过程中获得更多 privilege。实际来说，一旦设置了这个 flag，执行 setuid binary、setgid binary，或者带有 Linux file capabilities 的 file，都不会再授予超出 process 已有范围的额外 privilege。在 containerized 环境中，这一点很重要，因为很多 privilege-escalation chains 都依赖于找到一个在启动时会改变 privilege 的 executable。

从 defensive 的角度看，`no_new_privs` 不能替代 namespaces、seccomp 或 capability dropping。它是一个 reinforcement layer。它会阻止在已经获得 code execution 之后进一步 escalation 的某一类后续步骤。这使得它在 images 中包含 helper binaries、package-manager artifacts 或 legacy tools 的环境里尤其有价值，因为这些东西在与部分 compromise 结合时否则会很危险。

## Operation

支撑这种行为的 kernel flag 是 `PR_SET_NO_NEW_PRIVS`。一旦它被设置到 process 上，后续的 `execve()` 调用就不能再增加 privilege。关键细节是，process 仍然可以运行 binaries；它只是不能再利用这些 binaries 去跨越 kernel 本来会认可的 privilege boundary。

kernel 的行为同样是**继承且不可逆**的：一旦 task 设置了 `no_new_privs`，这个 bit 会在 `fork()`、`clone()` 和 `execve()` 之间被继承，并且之后不能再被取消。这在 assessments 中很有用，因为 container process 上只要看到 `NoNewPrivs: 1`，通常就意味着其后代也应该保持该模式，除非你看到的是完全不同的 process tree。

在面向 Kubernetes 的环境中，`allowPrivilegeEscalation: false` 会将这种行为映射到 container process。对于 Docker 和 Podman 这类 runtime，通常需要通过 security option 显式启用。到了 OCI layer，同样的概念表现为 `process.noNewPrivileges`。

## Important Nuances

`no_new_privs` 阻止的是 **exec-time** 的 privilege gain，而不是所有 privilege change。尤其是：

- setuid 和 setgid 迁移在 `execve()` 过程中将不再生效
- file capabilities 不会在 `execve()` 时加入到 permitted set
- AppArmor 或 SELinux 等 LSMs 不会在 `execve()` 后放宽约束
- already-held privilege 仍然是 already-held privilege

最后这一点在实际操作中很重要。如果 process 已经以 root 运行、已经拥有危险 capability，或者已经能够访问强大的 runtime API 或可写的 host mount，那么设置 `no_new_privs` 并不能消除这些暴露。它只会移除 privilege-escalation chain 中常见的一个 **next step**。

另外要注意，这个 flag 不会阻止那些不依赖 `execve()` 的 privilege change。例如，一个已经足够 privileged 的 task 仍然可能直接调用 `setuid(2)`，或者通过 Unix socket 接收到一个 privileged file descriptor。这也是为什么 `no_new_privs` 应该与 [seccomp](seccomp.md)、capability sets 和 namespace exposure 一起看，而不是作为独立答案。

## Lab

Inspect the current process state:
```bash
grep NoNewPrivs /proc/self/status
```
与运行时启用了该标志的 container 比较：
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
在 hardened workload 上，结果应显示 `NoNewPrivs: 1`。

你也可以通过一个 setuid binary 来演示实际效果：
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
这个比较的重点不是 `su` 是否普遍可被利用，而是同一个镜像在 `execve()` 是否仍然被允许跨越权限边界时，行为可能会有非常大的不同。

## Security Impact

如果缺少 `no_new_privs`，容器内的立足点仍然可能通过 setuid helpers 或带有 file capabilities 的 binary 被提升权限。若它存在，这些 exec 后的权限变更就会被切断。这个影响在那类带有大量应用本来根本不需要的工具的宽泛基础镜像中尤其相关。

还有一个重要的 seccomp 交互。无特权任务通常需要先设置 `no_new_privs`，然后才能在 filter mode 中安装 seccomp filter。这也是为什么加固过的容器经常同时启用 `Seccomp` 和 `NoNewPrivs`。从攻击者角度看，两者都开启通常意味着环境是被有意配置过的，而不是偶然如此。

## Misconfigurations

最常见的问题就是在本来兼容的环境里没有启用这个控制。在 Kubernetes 中，保留 `allowPrivilegeEscalation` 启用通常就是最常见的运维失误。在 Docker 和 Podman 中，省略相关的 security option 也会产生同样的效果。另一个反复出现的失败模式是以为只要容器不是 "privileged"，exec 时的权限转换就自动不重要了。

一个更隐蔽的 Kubernetes 陷阱是，当容器是 `privileged`，或者具有 `CAP_SYS_ADMIN` 时，`allowPrivilegeEscalation: false` **不会** 按人们预期的方式生效。Kubernetes API 文档说明，在这些情况下 `allowPrivilegeEscalation` 实际上总是 true。实际上，这意味着该字段应被视为最终安全态势中的一个信号，而不是保证运行时最终一定会得到 `NoNewPrivs: 1`。

## Abuse

如果没有设置 `no_new_privs`，首先要问的是镜像里是否包含仍然可以提升权限的 binary：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
有趣的结果包括：

- `NoNewPrivs: 0`
- `su`、`mount`、`passwd` 之类的 setuid helpers，或发行版特定的 admin tools
- 带有 file capabilities、可授予 network 或 filesystem privileges 的 binaries

在真实的 assessment 中，这些发现本身并不能证明可用的 escalation，但它们能准确指出下一步值得测试的 binaries。

在 Kubernetes 中，也要验证 YAML intent 是否与 kernel reality 一致：
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
有意思的组合包括：

- Pod spec 中 `allowPrivilegeEscalation: false`，但 container 中 `NoNewPrivs: 0`
- 存在 `cap_sys_admin`，这会让 Kubernetes 字段的可信度大大降低
- `Seccomp: 0` 且 `NoNewPrivs: 0`，这通常表示 runtime 整体防护姿态被明显削弱，而不是单一的孤立失误

### Full Example: In-Container Privilege Escalation Through setuid

这个控制通常防止的是 **in-container privilege escalation**，而不是直接逃逸到 host。 如果 `NoNewPrivs` 是 `0` 并且存在 setuid helper，就明确测试它：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
如果存在一个已知的 setuid binary 且可正常使用，尝试以一种能保留 privilege transition 的方式启动它：
```bash
/bin/su -c id 2>/dev/null
```
这本身不会逃逸容器，但它可以将容器内的低权限立足点转换为 container-root，而这通常会成为之后通过 mounts、runtime sockets 或面向 kernel 的 interfaces 进行 host escape 的前提条件。

## Checks

这些 checks 的目标是确认 exec-time privilege gain 是否被阻止，以及如果没有被阻止，image 中是否仍然包含会产生影响的 helpers。
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
What is interesting here:

- `NoNewPrivs: 1` is usually the safer result.
- `NoNewPrivs: 0` means setuid and file-cap based escalation paths remain relevant.
- `NoNewPrivs: 1` plus `Seccomp: 2` is a common sign of a more intentional hardening posture.
- A Kubernetes manifest that says `allowPrivilegeEscalation: false` is useful, but the kernel status is the ground truth.
- A minimal image with few or no setuid/file-cap binaries gives an attacker fewer post-exploitation options even when `no_new_privs` is missing.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 通过 `--security-opt no-new-privileges=true` 显式启用；也可以通过 `dockerd --no-new-privileges` 设置 daemon 级默认值 | 省略该 flag，`--privileged` |
| Podman | 默认未启用 | 通过 `--security-opt no-new-privileges` 或等效的 security configuration 显式启用 | 省略该 option，`--privileged` |
| Kubernetes | 由 workload policy 控制 | `allowPrivilegeEscalation: false` 会请求该效果，但 `privileged: true` 和 `CAP_SYS_ADMIN` 会让它实际上仍然为 true | `allowPrivilegeEscalation: true`，`privileged: true`，添加 `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | 遵循 Kubernetes workload settings / OCI `process.noNewPrivileges` | 通常继承自 Pod security context 并转换为 OCI runtime config | 同 Kubernetes 行 |

这种保护经常缺失，只是因为没人开启它，而不是因为 runtime 不支持它。

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
