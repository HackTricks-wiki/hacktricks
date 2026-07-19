# DDexec / EverythingExec

{{#include ../../../../banners/hacktricks-training.md}}

## 上下文

在 Linux 中，要运行一个程序，该程序必须作为文件存在，并且必须能够通过文件系统层次结构以某种方式访问它（这正是 `execve()` 的工作方式）。该文件可以位于磁盘上，也可以位于内存中（tmpfs、memfd），但你需要一个文件路径。这使得控制 Linux 系统上运行的内容变得非常容易，也便于检测威胁和攻击者的工具，或者完全阻止它们尝试执行任何自己的内容（_例如_，不允许非特权用户在任何位置放置可执行文件）。

但这项技术将改变这一切。如果你无法启动所需的进程……**那么就劫持一个已经存在的进程**。

该技术允许你**绕过常见的保护技术，例如只读、noexec、文件名白名单、哈希白名单……**

## 依赖项

最终脚本依赖以下工具才能运行，这些工具必须能够在你攻击的系统中访问（默认情况下，你几乎可以在所有系统中找到它们）：
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
## The technique

如果你能够任意修改某个进程的内存，就可以接管该进程。这可用于劫持一个已经存在的进程，并将其替换为另一个程序。我们可以通过使用 `ptrace()` syscall（这要求你能够执行 syscalls，或系统上存在 gdb）来实现；或者，更有趣的是，写入 `/proc/$pid/mem`。

文件 `/proc/$pid/mem` 是进程整个地址空间的一对一映射（_例如_，在 x86-64 中范围为 `0x0000000000000000` 到 `0x7ffffffffffff000`）。这意味着，在偏移量 `x` 处读取或写入该文件，等同于读取或修改虚拟地址 `x` 处的内容。

现在，我们需要面对四个基本问题：

- 通常，只有 root 和文件的程序所有者可以修改它。
- ASLR。
- 如果我们尝试读取或写入程序地址空间中未映射的地址，就会收到 I/O 错误。

这些问题都有解决方案，虽然并不完美，但已经足够有效：

- 大多数 shell interpreters 都允许创建随后会被子进程继承的文件描述符。我们可以创建一个具有写权限、指向 shell 的 `mem` 文件的 fd……这样，使用该 fd 的子进程就能够修改 shell 的内存。
- ASLR 甚至不是问题；我们可以检查 shell 的 `maps` 文件，或 procfs 中的任何其他文件，从而获取进程地址空间的信息。
- 因此，我们需要对该文件执行 `lseek()`。在 shell 中，除非使用臭名昭著的 `dd`，否则无法做到这一点。

### In more detail

这些步骤相对简单，不需要任何专业知识即可理解：

- 解析我们想要运行的 binary 和 loader，以确定它们需要哪些 mappings。然后构造一段“shell”code，大致执行 kernel 在每次调用 `execve()` 时所执行的相同步骤：
- 创建上述 mappings。
- 将 binaries 读取到其中。
- 设置 permissions。
- 最后使用程序的 arguments 初始化 stack，并放置 auxiliary vector（loader 所需）。
- 跳转到 loader，让它完成剩余工作（加载程序所需的 libraries）。
- 从 `syscall` 文件中获取进程在执行的 syscall 结束后将要返回的地址。
- 覆盖该位置；该位置将是 executable 的，并使用我们的 shellcode 覆盖它（通过 `mem`，我们可以修改不可写的 pages）。
- 将我们想要运行的程序传递到进程的 stdin（该“shell”code 会对其执行 `read()`）。
- 此时，由 loader 负责加载程序所需的 libraries，并跳转到程序中。

**Check out the tool in** [**https://github.com/arget13/DDexec**](https://github.com/arget13/DDexec)

## EverythingExec

`dd` 有几个替代方案，其中之一是 `tail`；目前默认使用的程序就是它，用于通过 `mem` 文件执行 `lseek()`（这也是使用 `dd` 的唯一目的）。这些替代方案包括：
```bash
tail
hexdump
cmp
xxd
```
设置变量 `SEEKER` 可以更改所使用的 seeker，例如：
```bash
SEEKER=cmp bash ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
如果你发现脚本中尚未实现的其他有效 seeker，仍然可以通过设置 `SEEKER_ARGS` 变量来使用它：
```bash
SEEKER=xxd SEEKER_ARGS='-s $offset' zsh ddexec.sh ls -l <<< $(base64 -w0 /bin/ls)
```
拦截这个，EDR。

## 参考资料

- [https://github.com/arget13/DDexec](https://github.com/arget13/DDexec)

{{#include ../../../../banners/hacktricks-training.md}}
