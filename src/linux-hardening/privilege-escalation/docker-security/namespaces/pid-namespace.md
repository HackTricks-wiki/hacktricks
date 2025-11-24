# PID 命名空间

{{#include ../../../../banners/hacktricks-training.md}}

## Basic Information

PID（进程标识符）命名空间是 Linux kernel 的一个特性，通过使一组进程拥有自己独立的一组唯一 PID（与其他命名空间的 PID 分离）来提供进程隔离。这在容器化中尤其有用，因为进程隔离对安全和资源管理至关重要。

当创建新的 PID 命名空间时，该命名空间中的第一个进程会被分配 PID 1。该进程成为新命名空间的 "init" 进程，负责管理该命名空间内的其他进程。随后在该命名空间中创建的每个进程在该命名空间内都会拥有唯一的 PID，这些 PID 与其他命名空间中的 PID 相互独立。

从位于 PID 命名空间内的进程视角来看，它只能看到同一命名空间内的其他进程。它不知道其他命名空间中的进程，也无法使用传统的进程管理工具（例如 `kill`、`wait` 等）与它们交互。这提供了一定程度的隔离，帮助防止进程互相干扰。

### How it works:

1. 当创建新进程时（例如，使用 `clone()` 系统调用），该进程可以被分配到新的或现有的 PID 命名空间。**如果创建了新的命名空间，该进程将成为该命名空间的 "init" 进程。**
2. **kernel** 维护了一个 **新命名空间中的 PID 与父命名空间中对应 PID 之间的映射**（即创建新命名空间的父命名空间）。该映射 **允许 kernel 在必要时转换 PID**，例如在不同命名空间的进程之间发送信号时。
3. **位于 PID 命名空间内的进程只能看到并与同一命名空间内的其他进程交互**。它们不知道其他命名空间中的进程，并且它们的 PID 在其命名空间内是唯一的。
4. 当 **PID 命名空间被销毁**（例如，当该命名空间的 "init" 进程退出时），**该命名空间内的所有进程都会被终止**。这确保了与该命名空间相关的所有资源被正确清理。

## Lab:

### Create different Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当 `unshare` 未使用 `-f` 选项执行时，会因为 Linux 处理新的 PID (Process ID) 命名空间的方式而遇到错误。关键细节和解决方案如下：

1. **问题说明**：

- Linux 内核允许进程通过 `unshare` 系统调用创建新的命名空间。然而，发起创建新的 PID 命名空间的进程（称为“unshare”进程）并不会进入该新命名空间；只有它的子进程会进入。
- 运行 %unshare -p /bin/bash% 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程仍然位于原始 PID 命名空间中。
- 在新命名空间中，`/bin/bash` 的第一个子进程会成为 PID 1。当该进程退出时，如果没有其他进程存在，会触发该命名空间的清理，因为 PID 1 承担接收孤儿进程的特殊角色。随后 Linux 内核会在该命名空间中禁用 PID 分配。

2. **后果**：

- PID 1 在新命名空间中退出会导致 `PIDNS_HASH_ADDING` 标志被清除。结果是 `alloc_pid` 函数在创建新进程时无法分配新的 PID，进而产生 "Cannot allocate memory" 错误。

3. **解决方法**：
- 可以通过对 `unshare` 使用 `-f` 选项来解决此问题。该选项会在创建新的 PID 命名空间后让 `unshare` fork 出一个新进程。
- 执行 %unshare -fp /bin/bash% 可确保 `unshare` 命令本身在新命名空间中成为 PID 1。随后 `/bin/bash` 和其子进程就安全地包含在该新命名空间内，从而防止 PID 1 提前退出并允许正常的 PID 分配。

通过确保 `unshare` 使用 `-f` 标志运行，可以正确维护新的 PID 命名空间，使 `/bin/bash` 及其子进程能够正常运行而不遇到内存分配错误。

</details>

通过挂载一个新的 `/proc` 文件系统实例（使用参数 `--mount-proc`），可以确保新的 mount 命名空间对该命名空间特定的进程信息具有一个**准确且隔离的视图**。

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查你的进程所在的命名空间
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### 查找所有 PID namespaces
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
注意，来自初始（default）PID namespace 的 root user 可以看到所有进程，甚至是那些位于新 PID namespaces 中的进程，这就是为什么我们能够看到所有 PID namespaces 的原因。

### 进入 PID namespace
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
When you enter inside a PID namespace from the default namespace, you will still be able to see all the processes. And the process from that PID ns will be able to see the new bash on the PID ns.

另外，你**只有在 root 的情况下才能进入另一个进程的 PID 命名空间**。并且你 **不能** **进入** 其他命名空间，除非有一个指向它的 **描述符**（例如 `/proc/self/ns/pid`）。

## 最近的利用笔记

### CVE-2025-31133: abusing `maskedPaths` to reach host PIDs

runc ≤1.2.7 允许控制容器镜像或通过 `runc exec` 启动的工作负载的攻击者，在 runtime 屏蔽敏感 procfs 条目之前替换容器端的 `/dev/null`。当竞态成功时，`/dev/null` 可以被变成指向任意宿主路径的符号链接（例如 `/proc/sys/kernel/core_pattern`），因此新的容器 PID 命名空间会突然继承对宿主全局 procfs 控件的读写访问，即使它从未离开过自己的命名空间。一旦 `core_pattern` 或 `/proc/sysrq-trigger` 可写，生成 coredump 或触发 SysRq 就会在宿主 PID 命名空间中导致代码执行或拒绝服务。

实际流程：

1. 构建一个 OCI bundle，其 rootfs 将 `/dev/null` 替换为指向你想要的宿主路径的链接（`ln -sf /proc/sys/kernel/core_pattern rootfs/dev/null`）。
2. 在修复之前启动容器，这样 runc 会将宿主的 procfs 目标 bind-mount 到该链接上。
3. 在容器命名空间内，向现在暴露的 procfs 文件写入（例如，将 `core_pattern` 指向一个反向 shell 助手），并使任一进程崩溃，以强制宿主内核以 PID 1 的上下文执行你的助手。

在启动之前，你可以快速审计一个 bundle 是否屏蔽了正确的文件：
```bash
jq '.linux.maskedPaths' config.json | tr -d '"'
```
如果运行时缺少你期望的屏蔽条目（或因为 `/dev/null` 消失而跳过它），应将该容器视为可能具有主机 PID 可见性。

### 命名空间注入（使用 `insject`）

NCC Group 的 `insject` 以 LD_PRELOAD payload 的形式加载，它在目标程序的晚期阶段（默认 `main`）挂钩，并在 `execve()` 之后发出一连串的 `setns()` 调用。这样你可以从主机（或另一个容器）进入目标的 PID namespace *之后*，在运行时初始化后附入受害者的 PID namespace，保留其 `/proc/<pid>` 视图，而无需将二进制文件复制到容器文件系统中。由于 `insject` 可以将加入 PID namespace 的操作延迟到 fork 时，你可以让一个线程保留在主机 namespace（具有 CAP_SYS_PTRACE），而另一个线程在目标 PID namespace 中执行，从而创建强大的调试或进攻原语。

示例用法：
```bash
sudo insject -S -p $(pidof containerd-shim) -- bash -lc 'readlink /proc/self/ns/pid && ps -ef'
```
滥用或防御 namespace injection 时的要点：

- 使用 `-S/--strict` 强制 `insject` 在线程已存在或 namespace joins 失败时中止，否则可能会留下部分迁移的线程横跨 host 和 container 的 PID 空间。
- 除非同时加入 mount namespace，否则绝不要附加仍然持有可写的 host file descriptors 的工具——否则 PID namespace 内的任何进程都可以 ptrace 你的 helper 并重用这些描述符来篡改 host 资源。

## 参考资料

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [container escape via "masked path" abuse due to mount race conditions (GitHub Security Advisory)](https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2)
- [Tool Release – insject: A Linux Namespace Injector (NCC Group)](https://www.nccgroup.com/us/research-blog/tool-release-insject-a-linux-namespace-injector/)

{{#include ../../../../banners/hacktricks-training.md}}
