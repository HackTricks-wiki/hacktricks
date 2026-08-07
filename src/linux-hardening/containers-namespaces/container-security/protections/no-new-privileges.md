# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` 是一种 kernel hardening feature，可防止进程在执行 `execve()` 时获得更多权限。实际而言，一旦设置该标志，执行 setuid binary、setgid binary 或带有 Linux file capabilities 的文件，都不会授予进程超出其原有权限的额外权限。在 containerized environments 中，这一点非常重要，因为许多 privilege-escalation chains 都依赖于在 image 中找到一个启动后会改变权限的 executable。

从防御角度看，`no_new_privs` 不能替代 namespaces、seccomp 或 capability dropping。它是一层 reinforcement。它会阻止一类特定的后续 escalation，这类 escalation 发生在已经获得 code execution 之后。因此，在 image 包含 helper binaries、package-manager artifacts 或 legacy tools 的环境中，它尤其有价值，因为这些内容在与 partial compromise 结合时可能带来危险。

## Operation

该行为背后的 kernel flag 是 `PR_SET_NO_NEW_PRIVS`。一旦为进程设置该 flag，后续的 `execve()` 调用就无法提升权限。重要细节是，进程仍然可以运行 binaries；只是无法利用这些 binaries 跨越 kernel 原本会认可的 privilege boundary。<sup>[[1]](#references)</sup>

该 kernel behavior 还具有 **继承性和不可逆性**：一旦 task 设置了 `no_new_privs`，该 bit 会通过 `fork()`、`clone()` 和 `execve()` 继承，之后无法取消。<sup>[[1]](#references)</sup> 这在 assessment 中很有用，因为 container process 上的单个 `NoNewPrivs: 1` 通常意味着其 descendants 也应保持该模式，除非你查看的是完全不同的 process tree。

在以 Kubernetes 为导向的 environments 中，`allowPrivilegeEscalation: false` 会为 container process 映射到此行为。<sup>[[2]](#references)</sup> 在 Docker 和 Podman 风格的 runtimes 中，通常通过 security option 显式启用等效功能。在 OCI layer 中，同一概念表示为 `process.noNewPrivileges`。

## Important Nuances

`no_new_privs` 会阻止 **exec-time** privilege gain，但不会阻止所有 privilege changes。<sup>[[1]](#references)</sup> 具体而言：

- setuid 和 setgid transitions 在 `execve()` 中会停止生效
- file capabilities 不会在 `execve()` 时添加到 permitted set
- AppArmor 或 SELinux 等 LSMs 不会在 `execve()` 后放宽 constraints
- 已经持有的 privilege 仍然是已经持有的 privilege

最后一点在实际操作中很重要。如果进程已经以 root 身份运行，已经拥有危险的 capability，或者已经能够访问强大的 runtime API 或可写的 host mount，那么设置 `no_new_privs` 并不会消除这些 exposures。它只会移除 privilege-escalation chain 中一个常见的 **next step**。

还要注意，该 flag 不会阻止不依赖 `execve()` 的 privilege changes。<sup>[[1]](#references)</sup> 例如，已经拥有足够 privilege 的 task 仍然可以直接调用 `setuid(2)`，或者通过 Unix socket 接收 privileged file descriptor。因此，应将 `no_new_privs` 与 [seccomp](seccomp.md)、capability sets 以及 namespace exposure 结合分析，而不是将其视为独立的解决方案。

## Lab

检查当前 process state：
```bash
grep NoNewPrivs /proc/self/status
```
将其与运行时启用该标志的容器进行比较：
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
在经过加固的 workload 上，结果应显示 `NoNewPrivs: 1`。

你还可以通过针对 setuid binary 的测试来演示实际效果：
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
比较的重点并不是说 `su` 普遍都可被利用，而是同一个 image 在 `execve()` 是否仍被允许跨越 privilege boundary 的情况下，可能表现得非常不同。

## Security Impact

如果缺少 `no_new_privs`，container 内的 foothold 仍可能通过 setuid helpers 或具有 file capabilities 的 binaries 被提升。如果启用该选项，这些 post-exec privilege changes 就会被切断。对于包含许多 application 实际上根本不需要的 utilities 的 broad base images，这一效果尤其值得关注。

这里还存在一个重要的 seccomp interaction。Unprivileged tasks 通常需要先设置 `no_new_privs`，之后才能以 filter mode 安装 seccomp filter。<sup>[[1]](#references)</sup> 这也是 hardened containers 通常会同时显示 `Seccomp` 和 `NoNewPrivs` 已启用的原因之一。从 attacker 的角度来看，同时看到这两项通常意味着该 environment 是经过 deliberate configuration 的，而不是偶然形成的。

## Misconfigurations

最常见的问题，就是在兼容启用该 control 的 environments 中没有启用它。在 Kubernetes 中，保持 `allowPrivilegeEscalation` 启用通常是 operational 上常见的默认错误。在 Docker 和 Podman 中，省略相关 security option 会产生相同效果。另一个反复出现的 failure mode 是认为 container 既然“不是 privileged”，exec-time privilege transitions 就自动无关紧要。

Kubernetes 中一个更隐蔽的 pitfall 是：当 container 为 `privileged` 或具有 `CAP_SYS_ADMIN` 时，`allowPrivilegeEscalation: false` **不会按照人们预期的方式**生效。Kubernetes API 文档说明，在这些情况下，`allowPrivilegeEscalation` 实际上始终为 true。<sup>[[2]](#references)</sup> 实际上，这意味着应将该字段视为 final posture 中的一个 signal，而不是 runtime 最终一定会得到 `NoNewPrivs: 1` 的 guarantee。

## Abuse

如果未设置 `no_new_privs`，首先要确认的是 image 中是否包含仍可提升 privilege 的 binaries：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
有价值的结果包括：

- `NoNewPrivs: 0`
- `su`、`mount`、`passwd` 或特定发行版的 admin 工具等 setuid helpers
- 具有可授予网络或文件系统权限的 file capabilities 的 binaries

在实际 assessment 中，这些发现本身并不能证明存在可行的 privilege escalation，但它们可以准确指出下一步值得测试的 binaries。

在 Kubernetes 中，还应验证 YAML 中的意图是否与 kernel 的实际状态一致：
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
有趣的组合包括：

- Pod spec 中的 `allowPrivilegeEscalation: false`，但容器中为 `NoNewPrivs: 0`
- 存在 `cap_sys_admin`，这会使 Kubernetes 字段的可信度大幅降低
- `Seccomp: 0` 和 `NoNewPrivs: 0`，这通常表示 runtime 的整体安全姿态被广泛削弱，而不是单个孤立错误

### 完整示例：通过 setuid 在容器内进行权限提升

此控制通常用于防止**容器内权限提升**，而不是直接防止 host escape。如果 `NoNewPrivs` 为 `0` 且存在 setuid helper，请明确测试：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
如果存在且可正常运行的已知 setuid 二进制文件，请尝试以能够保留权限转换的方式启动它：
```bash
/bin/su -c id 2>/dev/null
```
这本身不会逃逸 container，但可以将 container 内的低权限 foothold 转化为 container-root，而这通常会成为之后通过挂载、runtime sockets 或面向 kernel 的接口逃逸到主机的前提。

## Checks

这些 Checks 的目标是确认 exec-time privilege gain 是否被阻止，以及 image 中是否仍包含在未阻止时可能发挥作用的 helpers。
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
这里有哪些值得关注的内容：

- `NoNewPrivs: 1` 通常是更安全的结果。
- `NoNewPrivs: 0` 意味着基于 setuid 和 file-cap 的提权路径仍然值得关注。
- `NoNewPrivs: 1` 加上 `Seccomp: 2`，通常表明采取了更有意的 hardening 策略。
- Kubernetes manifest 中的 `allowPrivilegeEscalation: false` 很有用，但 kernel 状态才是实际依据。
- 即使缺少 `no_new_privs`，使用很少或完全不包含 setuid/file-cap binaries 的 minimal image，也会让 attacker 的 post-exploitation 选项更少。

## Runtime 默认设置

| Runtime / platform | 默认状态 | 默认行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 使用 `--security-opt no-new-privileges=true` 显式启用；也可以通过 `dockerd --no-new-privileges` 设置 daemon-wide 默认值 | 省略该 flag，使用 `--privileged` |
| Podman | 默认未启用 | 使用 `--security-opt no-new-privileges` 或等效的 security 配置显式启用 | 省略该 option，使用 `--privileged` |
| Kubernetes | 由 workload policy 控制 | `allowPrivilegeEscalation: false` 请求启用该效果，但 `privileged: true` 和 `CAP_SYS_ADMIN` 会使其实际上保持启用 | `allowPrivilegeEscalation: true`、`privileged: true`、添加 `CAP_SYS_ADMIN` |
| Kubernetes 下的 containerd / CRI-O | 遵循 Kubernetes workload 设置 / OCI `process.noNewPrivileges` | 通常从 Pod security context 继承，并转换为 OCI runtime 配置 | 与 Kubernetes 行相同 |

这项 protection 经常缺失，仅仅是因为没有人启用它，而不是因为 runtime 不支持它。

## References

- [1] [Linux kernel 文档：No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [2] [Kubernetes：为 Pod 或 Container 配置 Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)

{{#include ../../../../banners/hacktricks-training.md}}
