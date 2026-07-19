# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` 是一种 kernel hardening 功能，可阻止进程在执行 `execve()` 时获得更多权限。实际上，一旦设置该标志，执行 setuid binary、setgid binary 或带有 Linux file capabilities 的文件，都不会使进程获得超出其原有权限的额外权限。在 containerized environments 中，这一点很重要，因为许多 privilege-escalation 链都依赖于在 image 中找到一个启动后会改变权限的 executable。

从 defensive 角度来看，`no_new_privs` 不能替代 namespaces、seccomp 或 capability dropping。它是一层 reinforcement。它会阻止一类特定的后续 escalation，但前提是 code execution 已经被取得。这使其在以下环境中尤其有价值：image 中包含 helper binaries、package-manager artifacts 或 legacy tools，而这些内容在与 partial compromise 结合时可能造成危险。

## 操作

此行为背后的 kernel flag 是 `PR_SET_NO_NEW_PRIVS`。一旦为进程设置该 flag，之后的 `execve()` 调用就无法提升权限。需要注意的是，进程仍然可以运行 binaries；只是无法利用这些 binaries 跨越 kernel 原本会认可的 privilege boundary。

该 kernel 行为还具有 **继承性且不可逆**：一旦 task 设置了 `no_new_privs`，该 bit 会通过 `fork()`、`clone()` 和 `execve()` 继承，并且之后无法取消。在 assessments 中，这一点很有用，因为 container process 上的单个 `NoNewPrivs: 1` 通常意味着其 descendants 也应保持该模式，除非你查看的是一个完全不同的 process tree。

在 Kubernetes-oriented environments 中，`allowPrivilegeEscalation: false` 会为 container process 映射为此行为。在 Docker 和 Podman style runtimes 中，通常通过 security option 显式启用等效功能。在 OCI layer 中，同一概念表现为 `process.noNewPrivileges`。

## 重要注意事项

`no_new_privs` 会阻止 **exec-time** privilege gain，但不会阻止所有 privilege change。具体来说：

- setuid 和 setgid transitions 在跨越 `execve()` 时会停止工作
- file capabilities 不会在 `execve()` 时添加到 permitted set
- AppArmor 或 SELinux 等 LSMs 不会在 `execve()` 后放宽 constraints
- 已经持有的 privilege 仍然是已经持有的 privilege

最后一点在实际操作中很重要。如果进程已经以 root 运行，已经拥有 dangerous capability，或者已经能够访问 powerful runtime API 或 writable host mount，那么设置 `no_new_privs` 并不会消除这些 exposures。它只会移除 privilege-escalation 链中一个常见的 **下一步**。

还要注意，该 flag 不会阻止那些不依赖 `execve()` 的 privilege changes。例如，已经拥有足够 privilege 的 task 仍可能直接调用 `setuid(2)`，或通过 Unix socket 接收 privileged file descriptor。因此，应将 `no_new_privs` 与 [seccomp](seccomp.md)、capability sets 和 namespace exposure 一起分析，而不是将其视为 standalone answer。

## 实验

检查当前 process state：
```bash
grep NoNewPrivs /proc/self/status
```
将其与运行时启用该标志的容器进行比较：
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
在经过加固的 workload 上，结果应显示 `NoNewPrivs: 1`。

你还可以针对 setuid binary 演示实际效果：
```bash
docker run --rm debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'apt-get update >/dev/null 2>&1 && apt-get install -y passwd >/dev/null 2>&1 && grep NoNewPrivs /proc/self/status && /bin/su -c id 2>/dev/null'
```
比较的重点并不是说 `su` 普遍都可被利用，而是同一个 image 在 `execve()` 是否仍被允许跨越权限边界的情况下，行为可能大不相同。

## 安全影响

如果缺少 `no_new_privs`，容器内的 foothold 仍可能通过 setuid helpers 或具有 file capabilities 的 binaries 提权。如果启用了它，这些 post-exec 权限变更就会被切断。这一效果在广泛使用的 base images 中尤其重要，因为其中通常包含许多 application 根本不需要的 utilities。

此外，还存在一个重要的 seccomp 交互。Unprivileged tasks 通常必须先设置 `no_new_privs`，才能以 filter mode 安装 seccomp filter。这也是 hardened containers 通常同时显示 `Seccomp` 和 `NoNewPrivs` 已启用的原因之一。从 attacker 的角度看，同时看到这两项通常意味着环境是经过有意配置的，而不是意外形成的。

## 配置错误

最常见的问题是在控制项兼容的环境中， simply 没有启用它。在 Kubernetes 中，保持 `allowPrivilegeEscalation` 启用通常是默认的 operational mistake。在 Docker 和 Podman 中，省略相关 security option 也会产生相同效果。另一个反复出现的 failure mode 是认为 container 既然“not privileged”，exec-time privilege transitions 就自动无关紧要。

一个更隐蔽的 Kubernetes 陷阱是，当 container 为 `privileged` 或具有 `CAP_SYS_ADMIN` 时，`allowPrivilegeEscalation: false` **不会按照人们预期的方式生效**。Kubernetes API 文档说明，在这些情况下，`allowPrivilegeEscalation` 实际上始终为 true。实际上，这意味着该字段应被视为最终安全态势中的一个信号，而不是 runtime 最终一定具有 `NoNewPrivs: 1` 的保证。

## 滥用

如果未设置 `no_new_privs`，首先要确认的是 image 中是否包含仍可提升权限的 binaries：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
有趣的结果包括：

- `NoNewPrivs: 0`
- `su`、`mount`、`passwd` 或特定发行版的 admin tools 等 setuid helpers
- 具有 file capabilities、可授予 network 或 filesystem privileges 的 binaries

在真实 assessment 中，这些 findings 本身并不能证明存在可行的 privilege escalation，但它们能准确指出下一步值得测试的 binaries。

在 Kubernetes 中，还应验证 YAML intent 是否与 kernel reality 一致：
```bash
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)
kubectl get pod "$HOSTNAME" -n "$NS" -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}{.spec.containers[*].securityContext.privileged}{"\n"}{.spec.containers[*].securityContext.capabilities.add}{"\n"}' 2>/dev/null
grep -E 'NoNewPrivs|Seccomp' /proc/self/status
capsh --print 2>/dev/null | grep cap_sys_admin
```
有趣的组合包括：

- Pod spec 中的 `allowPrivilegeEscalation: false`，但容器中为 `NoNewPrivs: 0`
- 存在 `cap_sys_admin`，这会使 Kubernetes 字段的可信度大幅降低
- `Seccomp: 0` 和 `NoNewPrivs: 0`，这通常表示 runtime posture 被广泛削弱，而不是单一的孤立错误

### 完整示例：通过 setuid 在容器内进行 Privilege Escalation

此控制通常用于防止**容器内的 Privilege Escalation**，而不是直接防止 host escape。如果 `NoNewPrivs` 为 `0` 且存在 setuid helper，请明确测试：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
如果存在且可正常运行的已知 setuid binary，请尝试以能够保留权限转换的方式启动它：
```bash
/bin/su -c id 2>/dev/null
```
这本身不会逃逸容器，但可以将容器内的低权限立足点提升为 container-root，这通常是随后通过挂载、runtime sockets 或面向 kernel 的接口逃逸到主机的前提。

## 检查

这些检查旨在确认 exec-time privilege gain 是否被阻止，以及镜像中是否仍包含在未阻止时可能产生影响的 helpers。
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
grep -E 'Seccomp|NoNewPrivs' /proc/self/status   # Whether seccomp and no_new_privs are both active
setpriv --dump 2>/dev/null | grep -i no-new-privs   # util-linux view if available
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
docker inspect <container> | jq '.[0].HostConfig.SecurityOpt' 2>/dev/null   # Docker runtime options
kubectl get pod <pod> -n <ns> -o jsonpath='{.spec.containers[*].securityContext.allowPrivilegeEscalation}{"\n"}' 2>/dev/null
```
这里有什么值得注意：

- `NoNewPrivs: 1` 通常是更安全的结果。
- `NoNewPrivs: 0` 表示基于 setuid 和 file-cap 的提权路径仍然值得关注。
- `NoNewPrivs: 1` 加上 `Seccomp: 2`，通常表明采取了更有意的加固措施。
- Kubernetes manifest 中写入 `allowPrivilegeEscalation: false` 很有用，但 kernel 状态才是事实依据。
- 即使缺少 `no_new_privs`，包含很少或不包含 setuid/file-cap binaries 的 minimal image 也会让攻击者在 post-exploitation 阶段拥有更少的选择。

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 使用 `--security-opt no-new-privileges=true` 显式启用；也可以通过 `dockerd --no-new-privileges` 设置 daemon 级别的默认值 | 忽略该 flag、`--privileged` |
| Podman | 默认未启用 | 使用 `--security-opt no-new-privileges` 或等效的 security configuration 显式启用 | 忽略该 option、`--privileged` |
| Kubernetes | 由 workload policy 控制 | `allowPrivilegeEscalation: false` 请求启用该效果，但 `privileged: true` 和 `CAP_SYS_ADMIN` 会使其实际上保持启用 | `allowPrivilegeEscalation: true`、`privileged: true`、添加 `CAP_SYS_ADMIN` |
| containerd / CRI-O under Kubernetes | 遵循 Kubernetes workload settings / OCI `process.noNewPrivileges` | 通常从 Pod security context 继承，并转换为 OCI runtime config | 与 Kubernetes 行相同 |

这项 protection 经常缺失，仅仅是因为没有人启用它，而不是因为 runtime 不支持它。

## References

- [Linux kernel documentation: No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html)
- [Kubernetes: Configure a Security Context for a Pod or Container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
{{#include ../../../../banners/hacktricks-training.md}}
