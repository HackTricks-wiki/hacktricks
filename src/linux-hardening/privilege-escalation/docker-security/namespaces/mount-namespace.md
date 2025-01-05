# Mount Namespace

{{#include ../../../../banners/hacktricks-training.md}}

## 基本信息

挂载命名空间是一个Linux内核特性，它提供了一个进程组所看到的文件系统挂载点的隔离。每个挂载命名空间都有自己的一组文件系统挂载点，**对一个命名空间中挂载点的更改不会影响其他命名空间**。这意味着在不同挂载命名空间中运行的进程可以对文件系统层次结构有不同的视图。

挂载命名空间在容器化中特别有用，其中每个容器应该有自己的文件系统和配置，与其他容器和主机系统隔离。

### 工作原理：

1. 当创建一个新的挂载命名空间时，它会用**来自其父命名空间的挂载点的副本**进行初始化。这意味着在创建时，新的命名空间与其父命名空间共享相同的文件系统视图。然而，命名空间内的任何后续挂载点更改将不会影响父命名空间或其他命名空间。
2. 当一个进程在其命名空间内修改挂载点，例如挂载或卸载文件系统时，**更改仅限于该命名空间**，不会影响其他命名空间。这允许每个命名空间拥有自己的独立文件系统层次结构。
3. 进程可以使用`setns()`系统调用在命名空间之间移动，或使用带有`CLONE_NEWNS`标志的`unshare()`或`clone()`系统调用创建新的命名空间。当一个进程移动到一个新命名空间或创建一个新命名空间时，它将开始使用与该命名空间关联的挂载点。
4. **文件描述符和inode在命名空间之间是共享的**，这意味着如果一个命名空间中的进程有一个指向文件的打开文件描述符，它可以**将该文件描述符传递给另一个命名空间中的进程**，并且**两个进程将访问同一个文件**。然而，由于挂载点的差异，文件的路径在两个命名空间中可能并不相同。

## 实验：

### 创建不同的命名空间

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
通过挂载新的 `/proc` 文件系统实例，如果使用参数 `--mount-proc`，您可以确保新的挂载命名空间具有 **特定于该命名空间的进程信息的准确和隔离的视图**。

<details>

<summary>错误：bash: fork: 无法分配内存</summary>

当 `unshare` 在没有 `-f` 选项的情况下执行时，由于 Linux 处理新的 PID（进程 ID）命名空间的方式，会遇到错误。关键细节和解决方案如下：

1. **问题解释**：

- Linux 内核允许进程使用 `unshare` 系统调用创建新的命名空间。然而，启动新 PID 命名空间创建的进程（称为 "unshare" 进程）并不会进入新的命名空间；只有它的子进程会进入。
- 运行 `%unshare -p /bin/bash%` 会在与 `unshare` 相同的进程中启动 `/bin/bash`。因此，`/bin/bash` 及其子进程位于原始 PID 命名空间中。
- 新命名空间中 `/bin/bash` 的第一个子进程成为 PID 1。当该进程退出时，如果没有其他进程，它会触发命名空间的清理，因为 PID 1 具有收养孤儿进程的特殊角色。然后，Linux 内核将禁用该命名空间中的 PID 分配。

2. **后果**：

- 新命名空间中 PID 1 的退出导致 `PIDNS_HASH_ADDING` 标志的清理。这导致 `alloc_pid` 函数在创建新进程时无法分配新的 PID，从而产生 "无法分配内存" 的错误。

3. **解决方案**：
- 通过在 `unshare` 中使用 `-f` 选项可以解决此问题。此选项使 `unshare` 在创建新的 PID 命名空间后分叉一个新进程。
- 执行 `%unshare -fp /bin/bash%` 确保 `unshare` 命令本身在新的命名空间中成为 PID 1。然后，`/bin/bash` 及其子进程安全地包含在这个新命名空间中，防止 PID 1 的过早退出，并允许正常的 PID 分配。

通过确保 `unshare` 以 `-f` 标志运行，新的 PID 命名空间得以正确维护，使得 `/bin/bash` 及其子进程能够正常运行而不会遇到内存分配错误。

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### 检查您的进程所在的命名空间
```bash
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### 查找所有挂载命名空间
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```

```bash
findmnt
```
### 进入挂载命名空间
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
此外，您只能**进入另一个进程命名空间，如果您是 root**。并且您**不能**在没有指向它的描述符的情况下**进入**其他命名空间（例如 `/proc/self/ns/mnt`）。

因为新挂载仅在命名空间内可访问，所以命名空间可能包含只能从中访问的敏感信息。

### 挂载某些内容
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```

```
# findmnt # List existing mounts
TARGET                                SOURCE                                                                                                           FSTYPE     OPTIONS
/                                     /dev/mapper/web05--vg-root

# unshare --mount  # run a shell in a new mount namespace
# mount --bind /usr/bin/ /mnt/
# ls /mnt/cp
/mnt/cp
# exit  # exit the shell, and hence the mount namespace
# ls /mnt/cp
ls: cannot access '/mnt/cp': No such file or directory

## Notice there's different files in /tmp
# ls /tmp
revshell.elf

# ls /mnt/tmp
krb5cc_75401103_X5yEyy
systemd-private-3d87c249e8a84451994ad692609cd4b6-apache2.service-77w9dT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-resolved.service-RnMUhT
systemd-private-3d87c249e8a84451994ad692609cd4b6-systemd-timesyncd.service-FAnDql
vmware-root_662-2689143848

```
## 参考

- [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)
- [https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux](https://unix.stackexchange.com/questions/464033/understanding-how-mount-namespaces-work-in-linux)

{{#include ../../../../banners/hacktricks-training.md}}
