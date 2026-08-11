# 文件系统、Inodes 与恢复

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse 通常与混淆可见路径和其背后对象之间的关系有关。

磁盘镜像可能隐藏另一个文件系统。<sup>[[1]](#references)</sup> 可写挂载可能被特权任务使用。

Hardlinks 可能通过不同名称暴露同一个 inode。<sup>[[3]](#references)</sup> 已删除的文件仍可能通过打开的文件描述符读取。<sup>[[5]](#references)[[6]](#references)</sup>

本页面重点介绍该技术，而不是某个特定的 lab 或 target。

## 磁盘镜像与循环挂载

常规文件可以包含完整的文件系统，因此磁盘镜像在挂载后可以暴露第二个文件系统树。<sup>[[1]](#references)</sup>

备份镜像、复制的块设备、VM artifacts 或重命名的 blobs，可能因此包含 credentials、scripts、SSH keys、configuration files 或 flags，即使从外部看它们似乎没有用处。

使用 `file` 识别可能的镜像并对候选对象进行分类，使用 `blkid` 探测已识别的文件系统 metadata，并使用 `strings -a` 扫描整个文件中的可打印字符序列。<sup>[[10]](#references)[[11]](#references)[[12]](#references)</sup>
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
如果允许挂载，请使用带有 `ro` 的 loop mount，以只读方式附加该镜像；下面的 `find` 命令限制了检查深度和文件类型。<sup>[[1]](#references)[[4]](#references)</sup>
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
如果无法挂载，且镜像为 ext2/ext3/ext4，请使用 `debugfs` 直接检查其元数据。<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
该技术很有用，因为它可以将一个看起来正常的文件变成第二棵 filesystem tree。<sup>[[1]](#references)</sup> 将其视为恢复隐藏数据的方法，而不是其本身就能实现 privilege escalation 的手段。

## 可写挂载滥用

当更高权限的上下文随后信任可写挂载中的某些内容时，可写挂载就会变得危险。关键问题不仅是“我能否在这里写入？”，还包括“之后谁会从这里读取、执行、导入或加载内容？”。

使用 `findmnt` 检查已挂载的文件系统及其选项。<sup>[[9]](#references)</sup>

使用文档所述的 `find` 权限、类型和文件系统边界谓词查找可写挂载及可疑的使用者，然后使用递归 `grep` 搜索可能的使用者配置。<sup>[[4]](#references)[[20]](#references)</sup>
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
常见的滥用模式：

- cron job 或 systemd 服务从挂载点运行可写脚本。<sup>[[13]](#references)[[14]](#references)</sup>
- 特权服务从挂载点加载插件、配置、模板或辅助二进制文件。
- 挂载点包含 SUID 文件，并允许修改、替换或操纵路径。
- 容器或 chroot 暴露了一个由主机支持的路径，而该路径可从受限环境中写入。挂载命名空间提供独立的挂载层次结构，而 `chroot()` 只改变路径名解析，并不是完整的 sandbox。<sup>[[15]](#references)[[16]](#references)</sup>

使用相同 `find` 谓词的通用验证模式。<sup>[[4]](#references)</sup>
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
在 authorized lab 中证明 impact 时，请保持 payload 可观察且最小化，例如将 `id` 的输出写入临时文件。<sup>[[23]](#references)</sup> 核心 technique 是通过受信任的可写位置进行延迟执行。

## Inodes and Path Confusion

inode 是文件系统对象；path 只是指向它的名称。设备和 inode metadata 可帮助你跨文件系统区分对象，而 link count 则可暴露多个 hard link。<sup>[[3]](#references)</sup> 当进程仍保持文件打开时，被删除的 pathname 并不总意味着数据已经消失。<sup>[[5]](#references)</sup>

下面的 `find` predicates 会比较 inode identity、link count、设备边界和 timestamps。<sup>[[4]](#references)</sup>

使用 `ls -i` 和 `stat` metadata formats，按 inode 和设备比较文件。<sup>[[17]](#references)[[18]](#references)</sup>
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
使用 `find -samefile` 查找同一 inode 对应的所有可见路径名。<sup>[[4]](#references)</sup>
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
当你只有元数据时，使用 `find -inum` 直接按 inode 编号搜索。<sup>[[4]](#references)</sup>
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
当文件以意外的名称出现、应用程序验证一个路径却使用另一个路径，或者特权 wrapper 与一个在其他位置也可访问的 inode 交互时，这项技术非常有用。

## Hardlink Abuse

Hardlinks 为同一个 inode 创建多个名称。它们不像 symlinks 那样指向目标路径；它们是同一文件对象的等价名称。<sup>[[3]](#references)</sup>

使用 `find` 的权限和链接计数谓词查找具有多个 hardlinks 的 SUID 文件。<sup>[[4]](#references)</sup>
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
使用 `stat` 和 `find -samefile` 检查一个可疑文件。<sup>[[4]](#references)[[17]](#references)</sup>
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
为什么重要：

- 敏感文件可能通过不太明显的路径访问。
- SUID wrapper 可能隐藏在看起来不具备特权的名称之后。
- 清理操作删除一个 pathname 后，可能仍有另一个 hardlink 存在。

Linux 的 `fs.protected_hardlinks` sysctl 可以限制跨权限边界创建 hardlink。<sup>[[7]](#references)</sup> 现有的 hardlink 仍值得检查。

## 通过打开的 FD 恢复已删除文件

当进程保持文件打开时，删除其最后一个 pathname 不会立即释放文件；文件会一直存在，直到最后一个 descriptor 关闭。Linux 会在 `/proc/<pid>/fd/` 下公开这些 descriptor。<sup>[[5]](#references)[[6]](#references)</sup>

通过列出 `/proc` descriptor 并筛选 open-file 输出，可以查找已删除但仍处于打开状态的文件。<sup>[[5]](#references)[[6]](#references)[[18]](#references)[[19]](#references)[[20]](#references)</sup>
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
通过这些链接进行恢复取决于权限，因为取消引用 `/proc/<pid>/fd` 会受到 ptrace 访问检查和文件权限的限制。<sup>[[6]](#references)</sup>

在获得许可时，`readlink` 会显示描述符目标，而 `cp` 会复制其内容。<sup>[[21]](#references)[[22]](#references)</sup>
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
这是一种用于恢复已删除日志、临时 secrets、已丢弃的 binaries、轮换后的文件，或执行后被移除的 scripts 的实用技术。

## 使用 debugfs 恢复 ext 文件系统

在 ext2/ext3/ext4 文件系统上，`debugfs` 可以检查 inode 元数据，并从块设备或镜像中转储 inode 内容；不使用 `-w` 时，它会以只读方式打开文件系统。<sup>[[2]](#references)</sup> 尽可能对副本或只读镜像执行操作。

使用 `debugfs` 请求来列出目录项，并通过目录列表、inode 状态和 inode 到路径的检查来检查 inode。<sup>[[2]](#references)</sup>
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
使用 `debugfs dump` 命令转储已知 inode，然后使用 `file` 对恢复的输出进行分类。<sup>[[2]](#references)[[10]](#references)</sup>
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
这并不能保证恢复成功。恢复结果取决于文件系统状态、数据块是否已被重新使用，以及元数据是否仍然存在。对于 ext3/ext4，`debugfs` 手册指出，已删除 inode 的恢复可能会失败，因为已释放的 inode 数据块已不再可用。<sup>[[2]](#references)</sup> 该技术仍然很有价值，因为它可以让你检查 inode 级别的状态，而不必依赖正常的路径遍历。

## Inode Exhaustion and Ordering

当文件系统耗尽文件节点时，就会发生 inode 耗尽，即使磁盘仍有可用空间也是如此。<sup>[[8]](#references)[[17]](#references)</sup> 这通常会导致可靠性故障，但也可以解释 incident response 或 lab triage 期间出现的异常行为。

使用 `df -i` 报告 inode 信息，而不是块使用情况。<sup>[[8]](#references)</sup>

通过 `df` 以及使用 `find` 统计目录父级数量来检查 inode 压力。<sup>[[4]](#references)[[8]](#references)</sup>
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode 编号和时间戳也有助于在简单的实验室环境中重建活动记录。

下面的 `find` 格式指令会显示这些字段。<sup>[[4]](#references)</sup>
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
将排序视为线索，而非证据。复制操作、归档提取、文件系统类型、恢复操作以及并发写入都可能改变分配模式。

## 防御性说明

- 在分析期间，以只读方式挂载未知镜像。<sup>[[1]](#references)</sup>
- 将特权脚本、服务单元、插件和辅助路径放在用户可写挂载点之外。
- 在操作上适用时使用 `nosuid`、`nodev` 和 `noexec`；这些选项会禁用挂载点上的 set-ID/capability 执行、设备解释或直接二进制执行。<sup>[[1]](#references)</sup> 不要将它们视为完整的边界。
- 限制对 `/proc/<pid>/fd` 的访问；对这些链接进行解引用受 ptrace 访问检查和文件权限控制。<sup>[[6]](#references)</sup> 在可能的情况下，限制更广泛的进程元数据访问以及跨用户检查。
- 监控可写挂载点、指向特权文件的异常硬链接，以及已删除但仍处于打开状态的敏感文件。

## References

- [1] [mount(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/mount.8.html)
- [2] [debugfs(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/debugfs.8.html)
- [3] [inode(7) — Linux 手册页](https://man7.org/linux/man-pages/man7/inode.7.html)
- [4] [find(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/find.1.html)
- [5] [unlink(2) — Linux 手册页](https://man7.org/linux/man-pages/man2/unlink.2.html)
- [6] [proc_pid_fd(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html)
- [7] [/proc/sys/fs/ 文档 — Linux 内核文档](https://www.kernel.org/doc/html/latest/admin-guide/sysctl/fs.html)
- [8] [df(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/df.1.html)
- [9] [findmnt(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/findmnt.8.html)
- [10] [file(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/file.1.html)
- [11] [blkid(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/blkid.8.html)
- [12] [strings(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/strings.1.html)
- [13] [crontab(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/crontab.5.html)
- [14] [systemd.service(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/systemd.service.5.html)
- [15] [mount_namespaces(7) — Linux 手册页](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html)
- [16] [chroot(2) — Linux 手册页](https://man7.org/linux/man-pages/man2/chroot.2.html)
- [17] [stat(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/stat.1.html)
- [18] [ls(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/ls.1.html)
- [19] [lsof(8) — Linux 手册页](https://man7.org/linux/man-pages/man8/lsof.8.html)
- [20] [grep(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/grep.1.html)
- [21] [readlink(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/readlink.1.html)
- [22] [cp(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/cp.1.html)
- [23] [id(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/id.1.html)
{{#include ../../banners/hacktricks-training.md}}
