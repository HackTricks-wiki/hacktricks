# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## 初始信息收集

### 基本信息

首先，建议准备一个包含**已知可靠的 binaries 和 libraries**的 **USB**（可以直接获取 ubuntu，然后复制其中的 _/bin_、_/sbin_、_/lib,_ 和 _/lib64_ 文件夹），接着挂载 USB，并修改 env variables 以使用这些 binaries：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
配置系统以使用可靠且已知的 binaries 后，便可以开始**提取一些基本信息**：
```bash
date #Date and time (Clock may be skewed, Might be at a different timezone)
uname -a #OS info
ifconfig -a || ip a #Network interfaces (promiscuous mode?)
ps -ef #Running processes
netstat -anp #Proccess and ports
lsof -V #Open files
netstat -rn; route #Routing table
df; mount #Free space and mounted devices
free #Meam and swap space
w #Who is connected
last -Faiwx #Logins
lsmod #What is loaded
cat /etc/passwd #Unexpected data?
cat /etc/shadow #Unexpected data?
find /directory -type f -mtime -1 -print #Find modified files during the last minute in the directory
```
#### 可疑信息

在获取基本信息时，你应检查以下异常情况：

- **Root 进程**通常使用较低的 PID，因此如果发现某个 Root 进程拥有较大的 PID，可能需要怀疑
- 检查 `/etc/passwd` 中没有 shell 的用户的**已注册登录**
- 检查 `/etc/shadow` 中没有 shell 的用户的**密码哈希**

### Memory Dump

要获取运行中系统的内存，建议使用 [**LiME**](https://github.com/504ensicsLabs/LiME)。\
要对其进行**编译**，需要使用与受害机器相同的 **kernel**。

> [!TIP]
> 请记住，**不能在受害机器上安装 LiME 或任何其他东西**，因为这会对其进行多项更改

因此，如果你有一个版本完全相同的 Ubuntu，可以使用 `apt-get install lime-forensics-dkms`\
在其他情况下，你需要从 github 下载 [**LiME**](https://github.com/504ensicsLabs/LiME)，并使用正确的 kernel headers 对其进行编译。要**获取受害机器的准确 kernel headers**，只需将 `/lib/modules/<kernel version>` 目录**复制**到你的机器，然后使用它们**编译** LiME：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 支持 3 种 **格式**：

- Raw（将每个段连接在一起）
- Padded（与 raw 相同，但在右侧位中填充零）
- Lime（推荐的带元数据格式

LiME 还可以用于通过网络**发送转储**，而不是将其存储在系统中，例如：`path=tcp:4444`

### 磁盘映像

#### 关机

首先，你需要**关闭系统**。这并不总是可行，因为有时系统可能是公司无法承受停机的生产服务器。\
关闭系统有 **2 种方式**：**正常关机**和**“拔掉电源”关机**。前者会让**进程正常终止**，并使**文件系统**完成**同步**，但也会给可能存在的 **malware** **销毁证据**的机会。“拔掉电源”的方式可能会造成**一些信息丢失**（由于我们已经获取了内存映像，因此不会丢失太多信息），但 **malware 将没有任何机会**对此采取行动。因此，如果你**怀疑**可能存在 **malware**，只需在系统上执行 **`sync`** **命令**，然后拔掉电源。

#### 获取磁盘映像

需要注意的是，**在将计算机连接到任何与案件相关的设备之前**，你必须确认它将以**只读方式挂载**，以避免修改任何信息。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### 磁盘映像预分析

对不包含更多数据的磁盘映像进行成像。
```bash
#Find out if it's a disk image using "file" command
file disk.img
disk.img: Linux rev 1.0 ext4 filesystem data, UUID=59e7a736-9c90-4fab-ae35-1d6a28e5de27 (extents) (64bit) (large files) (huge files)

#Check which type of disk image it's
img_stat -t evidence.img
raw
#You can list supported types with
img_stat -i list
Supported image format types:
raw (Single or split raw file (dd))
aff (Advanced Forensic Format)
afd (AFF Multiple File)
afm (AFF with external metadata)
afflib (All AFFLIB image formats (including beta ones))
ewf (Expert Witness Format (EnCase))

#Data of the image
fsstat -i raw -f ext4 disk.img
FILE SYSTEM INFORMATION
--------------------------------------------
File System Type: Ext4
Volume Name:
Volume ID: 162850f203fd75afab4f1e4736a7e776

Last Written at: 2020-02-06 06:22:48 (UTC)
Last Checked at: 2020-02-06 06:15:09 (UTC)

Last Mounted at: 2020-02-06 06:15:18 (UTC)
Unmounted properly
Last mounted on: /mnt/disk0

Source OS: Linux
[...]

#ls inside the image
fls -i raw -f ext4 disk.img
d/d 11: lost+found
d/d 12: Documents
d/d 8193:       folder1
d/d 8194:       folder2
V/V 65537:      $OrphanFiles

#ls inside folder
fls -i raw -f ext4 disk.img 12
r/r 16: secret.txt

#cat file inside image
icat -i raw -f ext4 disk.img 16
ThisisTheMasterSecret
```
## 搜索已知 Malware

### 被修改的系统文件

Linux 提供了用于确保系统组件完整性的工具，这对于发现潜在的恶意文件至关重要。<sup>[[1]](#references)</sup>

- **基于 RedHat 的系统**：使用 `rpm -Va` 进行全面检查。
- **基于 Debian 的系统**：使用 `dpkg --verify` 进行初步验证，然后使用 `debsums | grep -v "OK$"`（先通过 `apt-get install debsums` 安装 `debsums`）来识别任何问题。

### Malware/Rootkit 检测工具

阅读以下页面，了解可用于查找 Malware 的工具：


{{#ref}}
malware-analysis.md
{{#endref}}

## 搜索已安装的程序

要在 Debian 和 RedHat 系统上有效搜索已安装的程序，可以结合使用系统日志、数据库以及对常见目录的手动检查。<sup>[[1]](#references)</sup>

- 对于 Debian，检查 _**`/var/lib/dpkg/status`**_ 和 _**`/var/log/dpkg.log`**_ 以获取软件包安装的详细信息，并使用 `grep` 筛选特定信息。
- RedHat 用户可以使用 `rpm -qa --root=/mntpath/var/lib/rpm` 查询 RPM 数据库，以列出已安装的软件包。

要查找手动安装的或通过这些软件包管理器之外的方式安装的软件，可以检查 _**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_ 和 _**`/sbin`**_ 等目录。将目录列表与特定于系统的命令结合使用，以识别未关联已知软件包的可执行文件，从而更全面地搜索所有已安装的程序。
```bash
# Debian package and log details
cat /var/lib/dpkg/status | grep -E "Package:|Status:"
cat /var/log/dpkg.log | grep installed
# RedHat RPM database query
rpm -qa --root=/mntpath/var/lib/rpm
# Listing directories for manual installations
ls /usr/sbin /usr/bin /bin /sbin
# Identifying non-package executables (Debian)
find /sbin/ -exec dpkg -S {} \; | grep "no path found"
# Identifying non-package executables (RedHat)
find /sbin/ –exec rpm -qf {} \; | grep "is not"
# Find exacuable files
find / -type f -executable | grep <something>
```
## 恢复已删除的运行中二进制文件

假设某个进程从 /tmp/exec 执行，之后该文件被删除。仍然可以将其提取出来。
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## 使用 SQLite 和 FTS5 进行 Syscall Trace 分诊

当进程仍在运行，或可以在 lab 中重新执行时，**`strace`** 可以提供快速的行为跟踪，无需 kernel modules 或完整的 EDR telemetry。对于大型 trace，避免直接读取原始日志，或将其粘贴到 LLM 中：将其存储在 **SQLite** database 中，并且只查询所需的最小子集。<sup>[[7]](#references)[[8]](#references)[[9]](#references)</sup>

> [!WARNING]
> 附加 `strace` 会改变进程 timing，并可能影响 race conditions 或其他脆弱的 bugs。条件允许时，优先在副本或 lab system 上进行复现。

### Capture

对于新进程：
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
对于正在运行的进程：
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
实用选项：

- `-ff`：跟踪 fork/线程，并保留每个进程的输出
- `-ttt`：使用 epoch 时间戳，便于时间线关联
- `-yy`：在可能的情况下，将文件描述符解析为其对应的路径/套接字
- `-s 4096`：避免长路径和缓冲区参数被截断

### 规范化

一种实用的 schema 是每个 syscall 一行、每个参数一行：
```sql
CREATE TABLE syscalls (
id        INTEGER PRIMARY KEY,
pid       INTEGER NOT NULL,
timestamp REAL    NOT NULL,
name      TEXT    NOT NULL,
ret_val   INTEGER,
errno     TEXT
);

CREATE TABLE syscall_args (
id         INTEGER PRIMARY KEY,
syscall_id INTEGER NOT NULL REFERENCES syscalls(id),
position   INTEGER NOT NULL,
raw        TEXT    NOT NULL,
type       INTEGER NOT NULL
);
```
这样可以避免尝试将异构的 syscall 行展平为单个宽表，并在 triage 期间保持 join 的可预测性。

### 使用 FTS5 为文本密集型参数建立索引

在大型 trace 中，使用 `LIKE "%...%"` 进行朴素的路径搜索会变得非常缓慢。为参数文本创建 FTS5 索引，然后改用该索引进行搜索：
```sql
CREATE VIRTUAL TABLE syscall_args_fts
USING fts5(raw, content='syscall_args', content_rowid='id');

INSERT INTO syscall_args_fts(rowid, raw)
SELECT id, raw FROM syscall_args;
```
示例：无需扫描每一行即可恢复 `/tmp` 下的文件活动：
```sql
SELECT s.timestamp, s.pid, s.name, a.position, a.raw
FROM syscall_args_fts f
JOIN syscall_args a ON a.id = f.rowid
JOIN syscalls s ON s.id = a.syscall_id
WHERE syscall_args_fts MATCH 'tmp'
AND s.name IN ('openat', 'stat', 'lstat', 'rename', 'unlink', 'execve')
ORDER BY s.timestamp;
```
### 高信号调查

- **PATH hijacking / fake sudo**：搜索 `~/.local/bin/` 下的写入以及 `chmod`/`rename` 活动，然后与之后对 `sudo` 等看起来具有特权的名称执行 `execve` 进行关联。
- **TOCTOU on temporary files**：围绕同一个 `/tmp/...` 路径，关联 `stat`、`access`、`openat`、`rename`、`unlink`、`link`、`symlink` 和 `execve`，以识别检查与使用之间的间隙。
- **崩溃根因**：将某个进程对文件的 `mmap` 与另一个进程对相同 inode/路径的写入或截断进行关联，然后检查信号/退出序列中是否存在 `SIGBUS`。
- **网络目标恢复**：筛选 `connect`、`sendto`、`sendmsg`、`recvfrom` 以及 socket 相关参数，以提取对端 IP 和端口。

### LLM 辅助的 trace 分析

如果希望 LLM 提供帮助，请提供一个**只读**的 SQLite handle，并将完整 schema 交给它。让它直接执行原始 SQL，而不是将数据库封装在功能受限的 helper functions 后面。对于 join、时间关联和 FTS 查询，这通常效果更好。

实用规则：

- 保持数据库只读，例如使用 `sqlite3 'file:trace.db?mode=ro'`。
- 向模型提供有效 `JOIN` 和 `FTS5 MATCH` 查询示例。
- 不要将原始的多 GB `strace` logs 粘贴到 prompt 中。
- 提出聚焦的问题，例如：
- "列出该程序写入的持久化文件。"
- "它是否在用户可控的 PATH 目录中创建或替换了可执行文件？"
- "解释为什么此 trace 以 SIGBUS 结束。"

## 检查 Autostart 位置

### Scheduled Tasks
```bash
cat /var/spool/cron/crontabs/*  \
/var/spool/cron/atjobs \
/var/spool/anacron \
/etc/cron* \
/etc/at* \
/etc/anacrontab \
/etc/incron.d/* \
/var/spool/incron/* \

#MacOS
ls -l /usr/lib/cron/tabs/ /Library/LaunchAgents/ /Library/LaunchDaemons/ ~/Library/LaunchAgents/
```
#### 排查：通过 0anacron 和可疑存根滥用 Cron/Anacron
攻击者通常会编辑每个 /etc/cron.*/ 目录下的 0anacron 存根，以确保定期执行。<sup>[[4]](#references)</sup>
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt：SSH 加固回滚与后门 shell
对 `sshd_config` 和系统账户 shell 的修改是常见的 post-exploitation 手段，用于保持访问权限。<sup>[[4]](#references)</sup>
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt：Cloud C2 标记（Dropbox/Cloudflare Tunnel）
- Dropbox API beacon 通常通过 HTTPS 使用 api.dropboxapi.com 或 content.dropboxapi.com，并携带 Authorization: Bearer tokens。
- 在 proxy/Zeek/NetFlow 中 Hunt 服务器发起的异常 Dropbox 出站流量。
- Cloudflare Tunnel（`cloudflared`）通过出站 443 端口提供备用 C2。<sup>[[4]](#references)</sup>
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### 服务

malware 可能作为服务安装的路径：

- **/etc/inittab**：调用 rc.sysinit 等初始化脚本，并进一步指向启动脚本。
- **/etc/rc.d/** 和 **/etc/rc.boot/**：包含服务启动脚本，后者存在于较旧的 Linux 版本中。
- **/etc/init.d/**：某些 Linux 版本（如 Debian）使用该目录存储启动脚本。
- 根据 Linux 变体的不同，服务也可能通过 **/etc/inetd.conf** 或 **/etc/xinetd/** 激活。
- **/etc/systemd/system**：用于存放 system 和 service manager 脚本的目录。
- **/etc/systemd/system/multi-user.target.wants/**：包含应在 multi-user runlevel 中启动的服务链接。
- **/usr/local/etc/rc.d/**：用于存放自定义或第三方服务。
- **\~/.config/autostart/**：用于存放用户特定的自动启动应用程序，可能成为针对用户的 malware 的隐藏位置。
- **/lib/systemd/system/**：由已安装软件包提供的系统范围默认 unit 文件。

#### 排查：systemd timers 和 transient units

systemd persistence 不仅限于 `.service` 文件。还应调查 `.timer` units、用户级 units，以及运行时创建的 **transient units**。
```bash
# Enumerate timers and inspect referenced services
systemctl list-timers --all
systemctl cat <name>.timer
systemctl cat <name>.service

# Search common system and user paths
find /etc/systemd/system /run/systemd/system /usr/lib/systemd/system -maxdepth 3 \( -name '*.service' -o -name '*.timer' \) -ls
find /home -path '*/.config/systemd/user/*' -type f \( -name '*.service' -o -name '*.timer' \) -ls

# Transient units created via systemd-run often land here
find /run/systemd/transient -maxdepth 2 -type f -ls 2>/dev/null

# Pull execution history for a suspicious unit
journalctl -u <name>.service
journalctl _SYSTEMD_UNIT=<name>.service
```
Transient units 很容易被遗漏，因为 `/run/systemd/transient/` 是**非持久化的**。如果你正在采集 live image，请在关机前获取它。

### 内核模块

Linux 内核模块通常被 malware 用作 rootkit 组件，并在系统启动时加载。与这些模块相关的重要目录和文件包括：

- **/lib/modules/$(uname -r)**：存放正在运行的内核版本对应的模块。
- **/etc/modprobe.d**：包含用于控制模块加载的配置文件。
- **/etc/modprobe** 和 **/etc/modprobe.conf**：用于全局模块设置的文件。

### 其他自动启动位置

Linux 使用各种文件在用户登录时自动执行程序，这些位置可能藏有 malware：

- **/etc/profile.d/**\*、**/etc/profile** 和 **/etc/bash.bashrc**：任何用户登录时都会执行。
- **\~/.bashrc**、**\~/.bash_profile**、**\~/.profile** 和 **\~/.config/autostart**：用户特定的文件，会在该用户登录时运行。
- **/etc/rc.local**：在所有系统服务启动后运行，标志着向多用户环境过渡的结束。

## 检查日志

Linux 系统通过各种日志文件记录用户活动和系统事件。这些日志对于识别未授权访问、malware 感染和其他安全事件至关重要。<sup>[[2]](#references)</sup> 重要日志文件包括：

- **/var/log/syslog**（Debian）或 **/var/log/messages**（RedHat）：记录系统范围的消息和活动。
- **/var/log/auth.log**（Debian）或 **/var/log/secure**（RedHat）：记录身份验证尝试，以及成功和失败的登录。
- 使用 `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` 筛选相关的身份验证事件。
- **/var/log/boot.log**：包含系统启动消息。
- **/var/log/maillog** 或 **/var/log/mail.log**：记录邮件服务器活动，有助于追踪与电子邮件相关的服务。
- **/var/log/kern.log**：存储内核消息，包括错误和警告。
- **/var/log/dmesg**：保存设备驱动程序消息。
- **/var/log/faillog**：记录失败的登录尝试，有助于调查安全 breach。
- **/var/log/cron**：记录 cron 任务的执行情况。
- **/var/log/daemon.log**：追踪后台服务活动。
- **/var/log/btmp**：记录失败的登录尝试。
- **/var/log/httpd/**：包含 Apache HTTPD 的错误和访问日志。
- **/var/log/mysqld.log** 或 **/var/log/mysql.log**：记录 MySQL 数据库活动。
- **/var/log/xferlog**：记录 FTP 文件传输。
- **/var/log/**：始终检查此处是否存在异常日志。

> [!TIP]
> Linux 系统日志和审计子系统可能会在入侵或 malware 事件中被禁用或删除。由于 Linux 系统上的日志通常包含有关恶意活动的最有用信息，因此入侵者会例行删除这些日志。因此，在检查可用日志文件时，务必查找缺失的时间段或顺序异常的条目，这可能表明日志遭到了删除或篡改。

### Journald triage (`journalctl`)

在现代 Linux 主机上，**systemd journal** 通常是获取**服务执行**、**身份验证事件**、**软件包操作**以及**内核/用户空间消息**的最高价值来源。在 live response 期间，尝试同时保留**持久化** journal（`/var/log/journal/`）和**运行时** journal（`/run/log/journal/`），因为攻击者的短暂活动可能只存在于后者中。<sup>[[5]](#references)</sup>
```bash
# List available boots and pivot around the suspicious one
journalctl --list-boots
journalctl -b -1

# Review a mounted image or copied journal directory offline
journalctl --directory /mnt/image/var/log/journal --list-boots
journalctl --directory /mnt/image/var/log/journal -b -1

# Inspect a single journal file and check integrity/corruption
journalctl --file system.journal --header
journalctl --file system.journal --verify

# High-signal filters
journalctl -u ssh.service
journalctl _SYSTEMD_UNIT=cron.service
journalctl _UID=0
journalctl _EXE=/usr/sbin/useradd
```
用于分类分析的有用 journal 字段包括 `_SYSTEMD_UNIT`、`_EXE`、`_COMM`、`_CMDLINE`、`_UID`、`_GID`、`_PID`、`_BOOT_ID` 和 `MESSAGE`。如果 journald 配置为不使用持久化存储，则只能在 `/run/log/journal/` 下找到最近的数据。

### Audit framework 分类分析（`auditd`）

如果启用了 `auditd`，当需要对文件更改、命令执行、登录活动或软件包安装进行**进程归因**时，优先使用它。<sup>[[6]](#references)</sup>
```bash
# Fast summaries
aureport --start today --summary -i
aureport --start today --login --failed -i
aureport --start today --executable -i

# Search raw events
ausearch --start today -m EXECVE -i
ausearch --start today -ua 1000 -m USER_CMD,EXECVE -i
ausearch --start today -m SERVICE_START,SERVICE_STOP -i

# Software installation/update events (especially useful on RHEL-like systems)
ausearch -m SOFTWARE_UPDATE -i
```
当规则通过密钥部署时，不要 grep 原始日志，而应从这些密钥进行 pivot：
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux 会为每个用户维护命令历史记录**，存储在：

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

此外，`last -Faiwx` 命令会提供用户登录列表。检查该列表，确认其中没有未知或异常的登录记录。

检查可能授予额外权限的文件：

- 检查 `/etc/sudoers`，确认是否授予了意外的用户权限。
- 检查 `/etc/sudoers.d/`，确认是否授予了意外的用户权限。
- 检查 `/etc/groups`，识别异常的组成员关系或权限。
- 检查 `/etc/passwd`，识别异常的组成员关系或权限。

一些应用也会生成自己的日志：

- **SSH**：检查 _\~/.ssh/authorized_keys_ 和 _\~/.ssh/known_hosts_，查找未授权的远程连接。
- **Gnome Desktop**：查看 _\~/.recently-used.xbel_，了解通过 Gnome 应用最近访问的文件。
- **Firefox/Chrome**：检查 _\~/.mozilla/firefox_ 或 _\~/.config/google-chrome_ 中的浏览器历史记录和下载记录，查找可疑活动。
- **VIM**：检查 _\~/.viminfo_，了解使用详情，例如访问过的文件路径和搜索历史。
- **Open Office**：检查最近访问的文档，以判断是否存在受危害的文件。
- **FTP/SFTP**：检查 _\~/.ftp_history_ 或 _\~/.sftp_history_ 中的日志，查找可能未经授权的文件传输。
- **MySQL**：调查 _\~/.mysql_history_ 中执行过的 MySQL 查询，这些查询可能暴露未经授权的数据库活动。
- **Less**：分析 _\~/.lesshst_ 中的使用历史，包括查看过的文件和执行过的命令。
- **Git**：检查 _\~/.gitconfig_ 和项目中的 _.git/logs_，了解仓库变更。

### USB 日志

[**usbrip**](https://github.com/snovvcrash/usbrip) 是一款完全使用 Python 3 编写的小型软件，可解析 Linux 日志文件（具体为 `/var/log/syslog*` 或 `/var/log/messages*`，取决于发行版），用于构建 USB 事件历史表。

了解**所有曾使用过的 USB 设备**非常重要。如果你拥有一份经过授权的 USB 设备列表，那么查找“违规事件”（使用不在该列表中的 USB 设备）会更加有用。

### 安装
```bash
pip3 install usbrip
usbrip ids download #Download USB ID database
```
### 示例
```bash
usbrip events history #Get USB history of your curent linux machine
usbrip events history --pid 0002 --vid 0e0f --user kali #Search by pid OR vid OR user
#Search for vid and/or pid
usbrip ids download #Downlaod database
usbrip ids search --pid 0002 --vid 0e0f #Search for pid AND vid
```
More examples and info inside the github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## 检查用户账户和登录活动

检查 _**/etc/passwd**_、_**/etc/shadow**_ 和 **安全日志**，查找在已知未授权事件前后短时间内创建或使用的异常名称或账户。同时，检查可能存在的 sudo brute-force attacks。\
此外，检查 _**/etc/sudoers**_ 和 _**/etc/groups**_ 等文件，查找授予用户的意外权限。\
最后，查找**没有密码**或密码**容易猜测**的账户。<sup>[[1]](#references)</sup>

## 检查文件系统

### 在 Malware Investigation 中分析文件系统结构

调查 malware incidents 时，文件系统的结构是重要的信息来源，可以揭示事件的发生顺序以及 malware 的内容。然而，malware authors 正在开发阻碍此类分析的技术，例如修改文件时间戳，或避开文件系统来存储数据。<sup>[[1]](#references)</sup>

为应对这些 anti-forensic methods，必须：

- **执行全面的时间线分析**，使用 **Autopsy** 可视化事件时间线，或使用 **Sleuth Kit** 的 `mactime` 获取详细的时间线数据。
- **调查系统 $PATH 中的异常脚本**，其中可能包括攻击者使用的 shell 或 PHP 脚本。
- **检查 `/dev` 中的异常文件**，因为该目录通常包含特殊文件，但也可能存放与 malware 相关的文件。
- **搜索隐藏文件或目录**，例如名称为 ".. "（两个点加空格）或 "..^G"（两个点加 control-G）的文件或目录，这些文件或目录可能隐藏恶意内容。
- 使用以下命令**识别 setuid root 文件**：`find / -user root -perm -04000 -print`。该命令会查找具有提升权限的文件，这些文件可能被攻击者滥用。
- **检查 inode 表中的删除时间戳**，以发现大量文件删除的情况，这可能表明存在 rootkits 或 trojans。
- 识别出一个恶意文件后，**检查相邻的 inode**，查找附近的其他恶意文件，因为它们可能是被一起放置的。
- **检查常见的 binary 目录**（_/bin_、_/sbin_）中最近修改的文件，因为这些文件可能已被 malware 修改。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> 注意，**攻击者**可以**修改** **时间**，使**文件看起来** **合法**，但他**无法修改** **inode**。如果你发现某个**文件**显示其创建和修改时间与同一文件夹中其他文件的**时间**相同，但其 **inode** 却**异常更大**，那么该文件的**时间戳已被修改**。

### 以 inode 为重点的快速分诊

如果怀疑存在反取证行为，请尽早运行以下以 inode 为重点的检查：
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
当可疑 inode 位于 EXT 文件系统镜像/设备上时，直接检查 inode 元数据：
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
有用字段：
- **Links**：如果为 `0`，当前没有目录项引用该 inode。
- **dtime**：inode 被取消链接时设置的删除时间戳。
- **ctime/mtime**：有助于将元数据/内容变更与事件时间线关联起来。

### Capabilities、xattrs 和基于 preload 的 userland rootkits

现代 Linux persistence 通常会避开明显的 **setuid** 二进制文件，转而滥用 **file capabilities**、**extended attributes** 和 dynamic loader。
```bash
# Enumerate file capabilities (think cap_setuid, cap_sys_admin, cap_dac_override)
getcap -r / 2>/dev/null

# Inspect extended attributes on suspicious binaries and libraries
getfattr -d -m - /path/to/suspicious/file 2>/dev/null

# Global preload hook affecting every dynamically linked binary
cat /etc/ld.so.preload 2>/dev/null
stat /etc/ld.so.preload 2>/dev/null

# If a suspicious library is referenced, inspect its metadata and links
ls -lah /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib 2>/dev/null | grep -E '\\.so(\\.|$)'
ldd /bin/ls
```
特别注意来自 **writable** 路径（例如 `/tmp`、`/dev/shm`、`/var/tmp` 或 `/usr/local/lib` 下异常位置）的 libraries。还要检查正常 package ownership 之外的、带有 capabilities 的 binaries，并将其与 package verification 结果（`rpm -Va`、`dpkg --verify`、`debsums`）进行关联分析。

## 比较不同 filesystem 版本中的文件

### Filesystem 版本比较摘要

要比较 filesystem 版本并精确定位变更，我们使用简化的 `git diff` 命令：<sup>[[3]](#references)</sup>

- **查找新文件**，比较两个目录：
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **对于修改过的内容**，列出更改，同时忽略特定行：
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **检测已删除的文件**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **筛选选项**（`--diff-filter`）有助于缩小范围，仅显示特定变更，例如新增（`A`）、删除（`D`）或修改（`M`）的文件。
- `A`：新增文件
- `C`：复制的文件
- `D`：删除的文件
- `M`：修改的文件
- `R`：重命名的文件
- `T`：类型变更（例如文件变为 symlink）
- `U`：未合并的文件
- `X`：未知文件
- `B`：损坏的文件

## 参考资料

- [1] [Linux 系统 Malware Forensics Field Guide：Digital Forensics Field Guides – 第 3 章](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [2] [Linux 日志解析](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [3] [git diff 文档 – --diff-filter 选项](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- [4] [Red Canary – 通过修补实现 persistence：DripDropper Linux malware 如何在 cloud 中移动](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [5] [Linux Journals 的 Forensic Analysis](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [6] [Red Hat Enterprise Linux 9 - 审计系统](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [7] [向 Pike 问好！](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [8] [strace](https://strace.io/)
- [9] [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
