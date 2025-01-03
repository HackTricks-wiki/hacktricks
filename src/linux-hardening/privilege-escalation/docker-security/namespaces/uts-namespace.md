# UTS Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

UTS（UNIX时间共享系统）命名空间是一个Linux内核特性，它提供了**两个系统标识符的隔离**：**主机名**和**NIS**（网络信息服务）域名。这种隔离允许每个UTS命名空间拥有**自己的独立主机名和NIS域名**，这在容器化场景中特别有用，因为每个容器应该看起来像是一个具有自己主机名的独立系统。

### 工作原理：

1. 当创建一个新的UTS命名空间时，它会以**从其父命名空间复制的主机名和NIS域名**开始。这意味着在创建时，新的命名空间**共享与其父命名空间相同的标识符**。然而，在命名空间内对主机名或NIS域名的任何后续更改将不会影响其他命名空间。
2. UTS命名空间内的进程**可以使用`sethostname()`和`setdomainname()`系统调用分别更改主机名和NIS域名**。这些更改是本地的，不会影响其他命名空间或主机系统。
3. 进程可以使用`setns()`系统调用在命名空间之间移动，或使用带有`CLONE_NEWUTS`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当进程移动到新的命名空间或创建一个时，它将开始使用与该命名空间关联的主机名和NIS域名。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -u [--mount-proc] /bin/bash
```
通过挂载新的 `/proc` 文件系统，如果使用参数 `--mount-proc`，您可以确保新的挂载命名空间具有 **特定于该命名空间的进程信息的准确和隔离的视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当 `unshare` 在没有 `-f` 选项的情况下执行时，由于 Linux 处理新的 PID（进程 ID）命名空间的方式，会遇到错误。关键细节和解决方案如下：

1. **问题说明**：

- Linux 内核允许进程使用 `unshare` 系统调用创建新的命名空间。然而，启动新 PID 命名空间创建的进程（称为 "unshare" 进程）并不会进入新的命名空间；只有它的子进程会进入。
- 运行 `%unshare -p /bin/bash%` 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程位于原始 PID 命名空间中。
- 新命名空间中 `/bin/bash` 的第一个子进程成为 PID 1。当该进程退出时，如果没有其他进程，它会触发命名空间的清理，因为 PID 1 具有收养孤儿进程的特殊角色。然后，Linux 内核将禁用该命名空间中的 PID 分配。

2. **后果**：

- 新命名空间中 PID 1 的退出导致 `PIDNS_HASH_ADDING` 标志的清理。这导致 `alloc_pid` 函数在创建新进程时无法分配新的 PID，从而产生 "无法分配内存" 的错误。

3. **解决方案**：
- 通过在 `unshare` 中使用 `-f` 选项可以解决此问题。此选项使 `unshare` 在创建新的 PID 命名空间后分叉一个新进程。
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身在新命名空间中成为 PID 1。然后，`/bin/bash` 及其子进程安全地包含在这个新命名空间中，防止 PID 1 提前退出，并允许正常的 PID 分配。

通过确保 `unshare` 以 `-f` 标志运行，新的 PID 命名空间得以正确维护，使得 `/bin/bash` 及其子进程能够正常运行，而不会遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### &#x20;检查您的进程所在的命名空间
```bash
ls -l /proc/self/ns/uts
lrwxrwxrwx 1 root root 0 Apr  4 20:49 /proc/self/ns/uts -> 'uts:[4026531838]'
```
### 查找所有 UTS 命名空间
```bash
sudo find /proc -maxdepth 3 -type l -name uts -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name uts -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### 进入 UTS 命名空间
```bash
nsenter -u TARGET_PID --pid /bin/bash
```
{{#include ../../../../banners/hacktricks-training.md}}
