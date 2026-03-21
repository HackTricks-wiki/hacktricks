# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` 是一个内核加固特性，防止进程在 execve() 期间获取更多权限。实际来说，一旦设置该标志，执行 setuid binary、setgid binary 或具有 Linux file capabilities 的文件不会授予超出进程已有的额外权限。在容器化环境中，这一点很重要，因为许多权限提升链依赖于在镜像内找到一个在启动时改变权限的可执行文件。

从防御角度看，`no_new_privs` 不能替代 namespaces、seccomp、或 capability dropping。它是一个加强层。它阻止了一类在已经获得代码执行后可能发生的后续提升。这使得它在镜像包含辅助可执行文件、package-manager artifacts 或遗留工具的环境中尤其有价值——这些工具在部分妥协的情况下可能会变得危险。

## 工作原理

这一行为背后的内核标志是 `PR_SET_NO_NEW_PRIVS`。一旦为进程设置，该进程后续的 `execve()` 调用就无法提升权限。重要的是，进程仍然可以运行二进制文件；只是不能利用这些二进制文件跨越内核本应允许的权限边界。

在面向 Kubernetes 的环境中，`allowPrivilegeEscalation: false` 将容器进程映射到此行为。在 Docker 和 Podman 风格的运行时中，等价设置通常通过安全选项显式启用。

## 实验

查看当前进程状态：
```bash
grep NoNewPrivs /proc/self/status
```
将其与 runtime 在 container 中启用该 flag 的情况进行比较：
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
在加固的工作负载上，结果应显示 `NoNewPrivs: 1`。

## 安全影响

如果未设置 `no_new_privs`，容器内的立足点仍可能通过 setuid helpers 或具有 file capabilities 的二进制文件提升权限。若设置了该项，则这些 post-exec 的权限更改将被切断。该影响在包含大量基础工具的宽泛基础镜像中尤为相关，这些镜像通常带有应用根本不需要的许多实用程序。

## 错误配置

最常见的问题是在本可兼容的环境中根本未启用该控制。在 Kubernetes 中，默认操作中常见的错误是将 `allowPrivilegeEscalation` 保持为启用。在 Docker 和 Podman 中，省略相关的安全选项会产生相同的效果。另一个反复出现的失败模式是假设因为容器是 “not privileged”，exec-time 的权限转换就自动无关紧要。

## 滥用

如果未设置 `no_new_privs`，首先要问的是镜像中是否包含仍能提升权限的二进制文件：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
有趣的结果包括：

- `NoNewPrivs: 0`
- setuid 帮助程序，例如 `su`、`mount`、`passwd` 或发行版特定的管理工具
- 具有授予网络或文件系统权限的 file capabilities 的二进制文件

在真实评估中，这些发现本身并不能证明存在可用的 escalation，但它们准确指出了值得接下来测试的二进制文件。

### 完整示例：通过 setuid 在容器内进行 Privilege Escalation

该控制通常是防止**容器内 privilege escalation**，而不是直接阻止主机逃逸。如果 `NoNewPrivs` 为 `0` 且存在 setuid 帮助程序，请显式测试它：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
如果已知的 setuid binary 存在且可用，尝试以保留权限转换的方式启动它：
```bash
/bin/su -c id 2>/dev/null
```
这本身并不能直接逃离容器，但它可以将容器内的低权限立足点转化为容器 root，这通常成为随后通过挂载点、运行时套接字或面向内核的接口进行宿主机逃逸的前提条件。

## 检查

这些检查的目的在于确定执行时提权是否被阻止，以及镜像是否仍包含在未被阻止时会造成影响的辅助程序。
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
这里有趣的是：

- `NoNewPrivs: 1` 通常是更安全的结果。
- `NoNewPrivs: 0` 意味着基于 setuid 和 file-cap 的提权路径仍然可行。
- 一个包含很少或没有 setuid/file-cap 二进制文件的最小镜像，即便在缺少 `no_new_privs` 时，也会给攻击者更少的 post-exploitation 选项。

## 运行时默认值

| Runtime / 平台 | 默认状态 | 默认行为 | 常见的手动放宽 |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 需要显式使用 `--security-opt no-new-privileges=true` 启用 | 省略该标志，`--privileged` |
| Podman | 默认未启用 | 需要显式使用 `--security-opt no-new-privileges` 或等效的安全配置来启用 | 省略该选项，`--privileged` |
| Kubernetes | 由工作负载策略控制 | `allowPrivilegeEscalation: false` 可启用该效果；许多工作负载仍将其保持为启用状态 | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | 遵循 Kubernetes 工作负载设置 | 通常从 Pod 的安全上下文继承 | 同 Kubernetes 行 |

此保护往往缺失，原因通常是没人开启它，而不是运行时不支持它。
