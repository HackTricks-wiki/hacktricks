# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## 背景

Linux 通常会从存储在磁盘或内存中的可执行文件运行程序。它可以通过路径名或文件描述符识别可执行文件，因此通常不一定需要文件系统路径名。<sup>[[2]](#references)</sup>

DDexec / EverythingExec 使用**已在运行的进程**的内存。[Linux Fileless Execution](../../../post-exploitation/linux-fileless-execution.md) 页面介绍了匿名文件执行以及相关的检测和取证收集；[Memory Bypasses overview](index.html#memory-bypasses) 还链接了 MemExec 和 Memdlopen。<sup>[[1]](#references)</sup>

此技术可让你**绕过常见的保护技术，例如只读、noexec、文件名白名单和哈希白名单**。<sup>[[1]](#references)</sup>

## 依赖项

最终脚本依赖以下工具才能运行，这些工具必须能在你攻击的系统上使用（默认情况下，你几乎可以在任何地方找到它们）：

```
dd
bash | zsh | ash (busybox)
head
tail
cut
grep
od
readlink
wc
tr
base64
```

## 该技术

如果你能够任意修改某个进程的内存，就可以接管该进程。你可以利用这一点劫持一个已存在的进程，并用另一个程序替换它。实现方式可以是使用 `ptrace()` 系统调用（这要求你能够执行系统调用，或者系统上有 gdb），也可以采用更有意思的方式：写入 `/proc/$pid/mem`。<sup>[[1]](#references)</sup>

文件 `/proc/$pid/mem` 与进程的整个地址空间一一映射（_例如_，在 x86-64 上，从 `0x0000000000000000` 到 `0x7ffffffffffff000`）。这意味着，在偏移 `x` 处读取或写入该文件，等同于读取或修改虚拟地址 `x` 处的内容。

现在，我们要解决四个基本问题：

- 通常只有 root 和该文件的程序所有者可以修改它。
- ASLR。
- 如果尝试读取或写入程序地址空间中未映射的地址，就会产生 I/O 错误。

这些问题都有解决方法，虽然并不完美，但效果不错：

- 大多数 shell 解释器都允许创建文件描述符，并由子进程继承。我们可以创建一个指向 shell 的 `mem` 文件且具有写权限的 fd……这样，使用该 fd 的子进程就能修改 shell 的内存。
- ASLR 根本不是问题，我们可以检查 shell 的 `maps` 文件，或 procfs 中的其他文件，以获取该进程地址空间的信息。
- 因此，我们需要对该文件执行 `lseek()`。在 shell 中无法做到这一点，除非使用臭名昭著的 `dd`。

### 详细说明

步骤相对简单，无需任何专业知识也能理解：<sup>[[1]](#references)</sup>

- 解析要运行的二进制文件和 loader，以确定它们需要哪些映射。然后构造一段“shell”code，大致执行内核在每次调用 `execve()` 时所执行的相同步骤：
  - 创建这些映射。
  - 将二进制文件读入映射区域。
  - 设置权限。
  - 最后，用程序的参数初始化栈，并放置辅助向量（loader 所需）。
  - 跳转到 loader，让它完成剩余工作（加载程序所需的库）。
- 从 `syscall` 文件中获取进程在执行系统调用后将返回到的地址。
- 覆写该位置；该位置可执行，我们可以通过 `mem` 修改不可写页面，并将其替换为我们的 shellcode。
- 将要运行的程序传入进程的 stdin（由这段“shell”code 执行 `read()` 读取）。
- 至此，loader 会负责为我们的程序加载所需的库，并跳转到程序中执行。

**查看此工具：** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)。<sup>[[1]](#references)</sup>

## EverythingExec

`dd` 有几种替代工具，其中一种是 `tail`，目前它是用于在 `mem` 文件中执行 `lseek()` 的默认程序（这原本是使用 `dd` 的唯一目的）。这些替代工具包括：<sup>[[1]](#references)</sup>

```bash
tail
hexdump
cmp
xxd
```

设置变量 `SEEKER` 可以更改所用的搜索器，例如：

```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

如果你找到脚本中尚未实现的其他有效 seeker，仍然可以通过设置 `SEEKER_ARGS` 变量来使用它：

```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```

阻止这个，EDR。

## References

- [1] [DDexec：在 Linux 上无文件、隐蔽地运行二进制文件的技术](https://github.com/arget13/DDexec)
- [2] [execveat(2) — Linux 手册页](https://manpages.debian.org/trixie/manpages-dev/execveat.2.en.html)
{{#include ../../../../banners/hacktricks-training.md}}
