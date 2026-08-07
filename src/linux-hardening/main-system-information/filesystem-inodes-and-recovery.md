# 文件系统、Inodes 与恢复

{{#include ../../banners/hacktricks-training.md}}

Filesystem abuse 通常与混淆可见路径和其背后对象之间的关系有关。磁盘映像可能隐藏另一个文件系统，可写挂载点可能被特权任务使用，hardlinks 可能通过不同名称暴露同一个 inode，而已删除的文件仍可能通过打开的文件描述符读取。

本页面重点介绍该 technique，而不是某个特定的 lab 或 target。

## 磁盘映像与 Loop Mounts

普通文件可以包含完整的文件系统。因此，备份映像、复制的块设备、VM artifacts 或重命名后的 blobs 可能包含 credentials、scripts、SSH keys、configuration files 或 flags，即使它们从外部看起来并无用途。

识别可能的映像：
```bash
file ./candidate
ls -lh ./candidate
blkid ./candidate 2>/dev/null
strings -a ./candidate | head -n 50
```
如果允许挂载，先以只读方式挂载未知镜像：
```bash
mkdir -p /tmp/imgmnt
sudo mount -o loop,ro ./candidate /tmp/imgmnt
find /tmp/imgmnt -maxdepth 3 -type f -ls 2>/dev/null
sudo umount /tmp/imgmnt
```
如果无法挂载，请直接检查文件系统元数据：
```bash
debugfs -R 'ls -l /' ./candidate 2>/dev/null
debugfs -R 'stat /' ./candidate 2>/dev/null
```
The technique is useful because it turns a normal-looking file into a second filesystem tree. Treat it as a way to recover hidden data, not as a privilege escalation by itself.

## Writable Mount Abuse

当更高权限的 context 后续信任其中的某些内容时，writable mount 会变得危险。重要的问题不只是“我能否在这里写入？”，还包括“之后谁会从这里读取、执行、import 或加载内容？”。

查找 writable mounts 和可疑的 consumers：
```bash
findmnt -o TARGET,SOURCE,FSTYPE,OPTIONS
find /mnt /media /srv /opt -xdev -type d -writable -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|backup|hook|plugin|sh |bash |python' /mnt /media /srv /opt 2>/dev/null | head -n 50
```
常见滥用模式：

- 特权 cron 或 systemd unit 从该 mount 运行可写脚本。
- 特权服务从该 mount 加载 plugins、config、templates 或 helper binaries。
- mount 包含 SUID 文件，并允许修改、替换或操纵路径。
- container 或 chroot 暴露了一个由 host 提供支持的路径，而该路径可从受限环境中写入。

通用验证模式：
```bash
find /mnt /media /srv /opt -xdev -perm -4000 -type f -ls 2>/dev/null
find /mnt /media /srv /opt -xdev -type f -writable -ls 2>/dev/null | head -n 50
```
在授权 lab 中证明影响时，应让 payload 可观察且保持最小化，例如将 `id` 输出写入临时文件。核心技术是通过受信任的可写位置进行延迟执行。

## Inodes 与 Path 混淆

inode 是文件系统对象；path 只是指向它的名称。这一点很重要，因为不同的 path 可以指向同一个 inode，而已删除的路径名并不总意味着数据已经消失。

按 inode 和设备比较文件：
```bash
ls -li /path/a /path/b
stat -c 'dev=%d inode=%i links=%h mode=%A owner=%U:%G path=%n' /path/a /path/b
```
查找同一 inode 的所有可见路径名：
```bash
find / -xdev -samefile /path/to/file -ls 2>/dev/null
```
当你只有元数据时，直接按 inode 编号搜索：
```bash
find / -xdev -inum <inode_number> -ls 2>/dev/null
```
当文件以意外的名称出现、应用程序验证一个路径却使用另一个路径，或特权 wrapper 与某个 inode 交互，而该 inode 还可通过其他位置访问时，这种 technique 很有用。

## Hardlink Abuse

Hardlinks 为同一个 inode 创建多个名称。它们不像 symlinks 那样指向目标路径；它们是同一个文件对象的等价名称。

查找具有多个 hardlink 的 SUID 文件：
```bash
find / -xdev -perm -4000 -type f -links +1 -ls 2>/dev/null
```
检查一个可疑文件：
```bash
stat /path/to/suspicious
find / -xdev -samefile /path/to/suspicious -ls 2>/dev/null
```
为什么这很重要：

- 敏感文件可能可以通过不太明显的路径访问。
- SUID wrapper 可能隐藏在一个看起来不像特权程序的名称后面。
- 清理操作删除一个 pathname 后，可能仍会留下另一个 hardlink。

现代内核和 mount options 可以限制 hardlink 的创建，以减少这类滥用，但现有的 hardlink 仍然值得检查。

## 通过打开的 FD 恢复已删除文件

当进程保持文件处于打开状态时，即使 pathname 已被删除，文件数据仍可能可用。Linux 会在 `/proc/<pid>/fd/` 下公开这些打开的 descriptor。

查找已删除但仍处于打开状态的文件：
```bash
ls -l /proc/*/fd/* 2>/dev/null | grep ' (deleted)' | head -n 50
lsof 2>/dev/null | grep deleted | head -n 50
```
在权限允许的情况下恢复数据：
```bash
readlink /proc/<pid>/fd/<fd>
cp /proc/<pid>/fd/<fd> /tmp/recovered-file
file /tmp/recovered-file
```
这是一种用于恢复已删除日志、临时 secrets、被丢弃的 binaries、轮换文件或执行后被移除的 scripts 的实用 technique。

## 使用 debugfs 进行 ext Recovery

在 ext filesystems 上，`debugfs` 可以检查 inode metadata，有时还能从 filesystem image 中 dump 文件内容。尽可能在副本或 read-only image 上操作。

列出条目并检查 inodes：
```bash
debugfs -R 'ls -l /' ./disk.img
debugfs -R 'stat <inode_number>' ./disk.img
debugfs -R 'ncheck <inode_number>' ./disk.img
```
转储已知 inode：
```bash
debugfs -R 'dump <inode_number> /tmp/recovered.bin' ./disk.img
file /tmp/recovered.bin
```
这并不保证能够恢复。结果取决于文件系统状态、数据块是否已被重用，以及元数据是否仍然存在。该技术仍然很有价值，因为它可以让你检查 inode 级别的状态，而无需依赖正常的 path traversal。

## Inode 耗尽与排序

当文件系统耗尽所有文件对象时，即使仍有可用磁盘空间，也会发生 inode 耗尽。它通常会导致可靠性故障，但也可以解释 incident response 或实验环境排查期间出现的异常行为。

检查 inode 压力：
```bash
df -h
df -i
find /var /tmp /home -xdev -printf '%h\n' 2>/dev/null | sort | uniq -c | sort -n | tail
```
Inode 编号和时间戳也可以帮助在简单的实验环境中重建活动：
```bash
find /path -xdev -printf '%i %TY-%Tm-%Td %TH:%TM %p\n' 2>/dev/null | sort -n | tail -n 50
find /path -xdev -newermt '2026-01-01' -ls 2>/dev/null
```
将排序视为线索，而非证据。复制操作、归档提取、文件系统类型、恢复操作以及并发写入都可能改变分配模式。

## 防御要点

- 在分析期间，以只读方式挂载未知镜像。
- 将特权脚本、服务单元、插件和辅助程序路径置于用户可写挂载点之外。
- 在操作上适用时使用 `nosuid`、`nodev` 和 `noexec`，但不要将它们视为完整的安全边界。
- 在可能的情况下，限制对 `/proc/<pid>/fd`、进程元数据以及跨用户进程检查的访问。
- 监控可写挂载点、指向特权文件的异常硬链接，以及已删除但仍处于打开状态的敏感文件。

{{#include ../../banners/hacktricks-training.md}}
