# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` 是一个内核强化特性，它阻止进程在通过 `execve()` 时获得更高的权限。实际来说，一旦设置该标志，执行 setuid 二进制、setgid 二进制或带有 Linux file capabilities 的文件不会授予超出进程已有权限的额外特权。在容器化环境中，这一点很重要，因为许多 privilege-escalation 链依赖于在镜像中找到可执行文件并在启动时改变特权。

从防御角度看，`no_new_privs` 不能替代 namespaces、seccomp 或 capability dropping。它是一个增强层，阻止在已获得代码执行后发生的一类后续升级。因而在镜像包含 helper binaries、package-manager artifacts 或遗留工具（在部分妥协的情况下会变得危险）的环境中，它尤其有价值。

## 工作原理

该行为背后的内核标志是 `PR_SET_NO_NEW_PRIVS`。一旦为某个进程设置，之后的 `execve()` 调用就无法提升权限。重要的细节是，进程仍然可以运行二进制；只是不能利用这些二进制跨越内核本来会接受的权限边界。

在以 Kubernetes 为导向的环境中，`allowPrivilegeEscalation: false` 将容器进程映射为此行为。在 Docker 和 Podman 风格的运行时中，等效选项通常通过安全选项显式启用。

## 实验

检查当前进程状态：
```bash
grep NoNewPrivs /proc/self/status
```
将其与运行时启用该标志的容器进行比较:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
在已加固的工作负载上，结果应显示 `NoNewPrivs: 1`。

## 安全影响

如果未设置 `no_new_privs`，容器内的立足点仍可能通过 setuid helpers 或带有 file capabilities 的二进制文件被提升权限。若已设置，则这些 post-exec privilege changes 会被切断。该影响在包含大量应用根本不需要的工具的宽泛基础镜像中尤其显著。

## 错误配置

最常见的问题是在本可兼容的环境中未启用该控制。在 Kubernetes 中，将 `allowPrivilegeEscalation` 保持为启用往往是常见的操作错误。在 Docker 和 Podman 中，省略相关的安全选项会产生同样的效果。另一个经常出现的失败模式是假设因为容器“not privileged”，exec-time privilege transitions 就自动不相关。

## 滥用

如果 `no_new_privs` 未设置，首先要问的是镜像中是否包含仍能提升权限的二进制文件：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
有趣的结果包括：

- `NoNewPrivs: 0`
- setuid 帮助程序，例如 `su`、`mount`、`passwd` 或发行版特定的管理工具
- 具有 file capabilities、能够授予网络或文件系统权限的二进制文件

在真实的评估中，这些发现本身并不能证明存在可用的提权，但它们准确地指出了接下来值得测试的二进制文件。

### 完整示例： In-Container Privilege Escalation Through setuid

此控制通常阻止 **in-container privilege escalation**，而不是直接进行主机逃逸。如果 `NoNewPrivs` 为 `0` 且存在 setuid helper，请对其进行明确测试：
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
如果已知的 setuid binary 存在并且可用，尝试以保留权限切换的方式启动它:
```bash
/bin/su -c id 2>/dev/null
```
这本身不会直接逃离 container，但它可以将容器内的低权限立足点升级为 container-root，通常这成为随后通过 mounts、runtime sockets 或 kernel-facing interfaces 实现 host escape 的前提条件。

## 检查

这些检查的目的是确定 exec-time privilege gain 是否被阻止，以及 image 是否仍包含在未阻止时会产生影响的 helpers。
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
有几点值得注意：

- `NoNewPrivs: 1` 通常是更安全的结果。
- `NoNewPrivs: 0` 意味着基于 setuid 和 file-cap 的提权路径仍然适用。
- 一个包含很少或没有 setuid/file-cap 二进制文件的最小镜像，即使在缺少 `no_new_privs` 时，也会给攻击者更少的 post-exploitation 选项。

## 运行时默认值

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 默认未启用 | 需要显式通过 `--security-opt no-new-privileges=true` 启用 | 省略该标志，或使用 `--privileged` |
| Podman | 默认未启用 | 需要显式通过 `--security-opt no-new-privileges` 或等效的安全配置启用 | 省略该选项，或使用 `--privileged` |
| Kubernetes | 受工作负载策略控制 | `allowPrivilegeEscalation: false` 启用该效果；许多工作负载仍将其保持为启用状态 | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | 遵循 Kubernetes 工作负载设置 | 通常从 Pod 的安全上下文继承 | 与 Kubernetes 行相同 |

该保护常常缺失，仅仅是因为没有人启用它，而不是因为运行时不支持它。
{{#include ../../../../banners/hacktricks-training.md}}
