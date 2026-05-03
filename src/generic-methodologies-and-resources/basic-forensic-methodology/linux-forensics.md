# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## 初始信息收集

### 基本信息

首先，建议准备一个带有**已知良好二进制文件和库**的**USB**（你可以直接获取 ubuntu 并复制 _/bin_、_/sbin_、_/lib_ 和 _/lib64_ 这些文件夹），然后挂载 USB，并修改环境变量以使用这些二进制文件：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
一旦你已经将系统配置为使用良好且已知的 binaries，就可以开始**提取一些基本信息**：
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
#### Suspicious information

While obtaining the basic information you should check for weird things like:

- **Root processes** usually run with low PIDS, so if you find a root process with a big PID you may suspect
- Check **registered logins** of users without a shell inside `/etc/passwd`
- Check for **password hashes** inside `/etc/shadow` for users without a shell

### Memory Dump

To obtain the memory of the running system, it's recommended to use [**LiME**](https://github.com/504ensicsLabs/LiME).\
To **compile** it, you need to use the **same kernel** that the victim machine is using.

> [!TIP]
> Remember that you **cannot install LiME or any other thing** in the victim machine as it will make several changes to it

So, if you have an identical version of Ubuntu you can use `apt-get install lime-forensics-dkms`\
In other cases, you need to download [**LiME**](https://github.com/504ensicsLabs/LiME) from github and compile it with correct kernel headers. To **obtain the exact kernel headers** of the victim machine, you can just **copy the directory** `/lib/modules/<kernel version>` to your machine, and then **compile** LiME using them:
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME 支持 3 种 **formats**：

- Raw（每个 segment 连接在一起）
- Padded（和 raw 相同，但在右侧位使用零填充）
- Lime（推荐的带 metadata 的格式）

LiME 也可以用来通过 **network** 发送 dump，而不是像这样将其存储在系统上：`path=tcp:4444`

### Disk Imaging

#### Shutting down

首先，你需要**关闭系统**。这并不总是可行，因为有时系统可能是公司无法承受关机的 production server。\
有 **2 种**关闭系统的方法，**normal shutdown** 和 **"plug the plug" shutdown**。第一种会让 **processes** 正常终止，并让 **filesystem** 得到 **synchronized**，但也会让可能存在的 **malware** 有机会**销毁证据**。"pull the plug" 方法可能会带来**一些信息丢失**（不过不会丢失太多，因为我们已经对 memory 做了 image），并且 **malware** 将**没有机会**采取任何行动。因此，如果你**怀疑**存在 **malware**，只需在系统上执行 **`sync`** **command**，然后直接拔掉电源。

#### Taking an image of the disk

需要注意的是，在**将你的计算机连接到与案件相关的任何东西之前**，你必须确保它将以 **read only** 方式 **mounted**，以避免修改任何信息。
```bash
#Create a raw copy of the disk
dd if=<subject device> of=<image file> bs=512

#Raw copy with hashes along the way (more secure as it checks hashes while it's copying the data)
dcfldd if=<subject device> of=<image file> bs=512 hash=<algorithm> hashwindow=<chunk size> hashlog=<hash file>
dcfldd if=/dev/sdc of=/media/usb/pc.image hash=sha256 hashwindow=1M hashlog=/media/usb/pc.hashes
```
### 磁盘镜像预分析

对一个不再有更多数据的磁盘镜像进行成像。
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

### Modified System Files

Linux 提供了用于确保 system components 完整性的工具，这对于发现可能有问题的文件至关重要。

- **基于 RedHat 的系统**：使用 `rpm -Va` 进行全面检查。
- **基于 Debian 的系统**：先用 `dpkg --verify` 进行初步验证，然后用 `debsums | grep -v "OK$"`（在通过 `apt-get install debsums` 安装 `debsums` 后）来识别任何问题。

### Malware/Rootkit Detectors

阅读以下页面，了解可用于查找 malware 的工具：


{{#ref}}
malware-analysis.md
{{#endref}}

## 搜索已安装程序

为了有效地在 Debian 和 RedHat 系统上搜索已安装程序，可以将 system logs 和 databases 与常见目录中的手动检查结合起来。

- 对于 Debian，检查 _**`/var/lib/dpkg/status`**_ 和 _**`/var/log/dpkg.log`**_，通过 `grep` 过滤特定信息以获取 package installations 的详细信息。
- RedHat 用户可以使用 `rpm -qa --root=/mntpath/var/lib/rpm` 查询 RPM database 来列出已安装的 packages。

为了发现手动安装或在这些 package managers 之外安装的软件，请查看像 _**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_ 和 _**`/sbin`**_ 这样的目录。将目录列表与系统特定命令结合起来，以识别不属于已知 packages 的 executables，从而增强你对所有已安装程序的搜索。
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

设想一个进程是从 /tmp/exec 执行的，然后该文件被删除了。仍然可以把它提取出来
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
## 使用 SQLite 和 FTS5 进行 Syscall Trace Triage

当进程仍在运行，或者可以在实验环境中重新执行时，**`strace`** 可以提供快速的行为 trace，而无需内核模块或完整的 EDR telemetry。对于大型 trace，不要直接读取原始日志，也不要把它粘贴到 LLM 中：将其存储到 **SQLite** 数据库，并只查询你需要的最小子集。

> [!WARNING]
> 附加 `strace` 会改变进程时序，可能影响竞态条件或其他脆弱 bug。尽可能优先在副本/实验系统上重现。

### Capture

对于一个新进程：
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log <command>
```
对于一个 live process:
```bash
strace -ff -ttt -yy -s 4096 -o /tmp/trace.log -p <PID>
```
实用选项：

- `-ff`: 跟随 forks/threads，并为每个进程保留独立输出
- `-ttt`: 使用 epoch 时间戳，便于时间线关联
- `-yy`: 在可能时将 file descriptors 解析为其对应的 backing paths/sockets
- `-s 4096`: 防止较长的 path 和 buffer 参数被截断

### Normalize

一个实用的 schema 是每个 syscall 一行、每个 argument 一行：
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
这避免了试图将异构的 syscall 行压平成一个单一的宽表，并在 triage 过程中保持 joins 可预测。

### 使用 FTS5 索引文本量大的参数

在大型 traces 上，使用 `LIKE "%...%"` 进行简单的 path hunting 会变得非常慢。为 argument text 创建一个 FTS5 index，然后改用它进行搜索：
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

- **PATH hijacking / fake sudo**: 搜索 `~/.local/bin/` 下的写入以及 `chmod`/`rename` 活动，然后将其与随后对看起来具有特权名称（如 `sudo`）的 `execve` 关联起来。
- **TOCTOU 在临时文件上**: 围绕同一个 `/tmp/...` 路径，在 `stat`, `access`, `openat`, `rename`, `unlink`, `link`, `symlink`, 和 `execve` 之间进行关联，以识别检查/使用间隙。
- **崩溃根因**: 将某个文件的 `mmap` 与另一个进程对同一 inode/path 的写入或截断关联起来，然后检查 signal/exit 序列中的 `SIGBUS`。
- **网络目标恢复**: 过滤 `connect`, `sendto`, `sendmsg`, `recvfrom`，以及与 socket 相关的参数，以提取对端 IP 和端口。

### LLM-assisted trace analysis

如果你想让 LLM 协助，提供一个**只读**的 SQLite 句柄，并给它完整 schema。让它直接发出原始 SQL，而不是把数据库封装在狭窄的 helper functions 后面。这通常在 joins、时间相关性分析和 FTS 检索方面效果更好。

实用规则：

- 保持数据库只读，例如使用 `sqlite3 'file:trace.db?mode=ro'`。
- 给模型提供有效 `JOIN` 和 `FTS5 MATCH` 查询的示例。
- 不要把原始的多 GB `strace` logs 粘贴到 prompt 里。
- 提出聚焦问题，例如：
- "列出这个程序写入的持久化文件。"
- "它是否在用户可控的 PATH 目录中创建或替换了可执行文件？"
- "解释为什么这个 trace 以 SIGBUS 结束。"

## Inspect Autostart locations

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
#### Hunt: Cron/Anacron abuse via 0anacron and suspicious stubs
攻击者经常编辑位于每个 /etc/cron.*/ 目录下的 0anacron stub，以确保定期执行。
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH hardening rollback and backdoor shells
对 sshd_config 和系统账户 shell 的更改在 post-exploitation 后很常见，用于保留访问权限。
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons typically use api.dropboxapi.com 或 content.dropboxapi.com 通过 HTTPS，并带有 Authorization: Bearer tokens。
- 在 proxy/Zeek/NetFlow 中排查服务器到外部异常的 Dropbox 流量。
- Cloudflare Tunnel (`cloudflared`) 通过出站 443 提供备用 C2。
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

恶意软件可能作为 service 安装的路径：

- **/etc/inittab**: 调用初始化脚本，如 rc.sysinit，并进一步指向启动脚本。
- **/etc/rc.d/** 和 **/etc/rc.boot/**: 包含用于 service 启动的脚本，后者见于较旧的 Linux 版本。
- **/etc/init.d/**: 在某些 Linux 版本（如 Debian）中用于存放启动脚本。
- 也可能通过 **/etc/inetd.conf** 或 **/etc/xinetd/** 激活，具体取决于 Linux 变体。
- **/etc/systemd/system**: system 和 service manager 脚本的目录。
- **/etc/systemd/system/multi-user.target.wants/**: 包含应在 multi-user runlevel 中启动的 service 的链接。
- **/usr/local/etc/rc.d/**: 用于自定义或第三方 service。
- **\~/.config/autostart/**: 用于用户特定的自动启动应用，可能是面向用户的恶意软件隐藏位置。
- **/lib/systemd/system/**: 安装包提供的系统范围默认 unit 文件。

#### Hunt: systemd timers and transient units

Systemd persistence 不仅限于 `.service` 文件。检查 `.timer` units、user-level units，以及运行时创建的 **transient units**。
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
Transient units are easy to miss because `/run/systemd/transient/` is **non-persistent**. If you are collecting a live image, grab it before shutdown.

### Kernel Modules

Linux kernel modules, often utilized by malware as rootkit components, are loaded at system boot. The directories and files critical for these modules include:

- **/lib/modules/$(uname -r)**: 保存当前运行的 kernel 版本对应的模块。
- **/etc/modprobe.d**: 包含用于控制模块加载的配置文件。
- **/etc/modprobe** and **/etc/modprobe.conf**: 用于全局模块设置的文件。

### Other Autostart Locations

Linux employs various files for automatically executing programs upon user login, potentially harboring malware:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: 在任何用户登录时执行。
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: 用户专属文件，在其登录时运行。
- **/etc/rc.local**: 在所有 system services 启动后运行，标志着向多用户环境过渡的结束。

## Examine Logs

Linux systems track user activities and system events through various log files. These logs are pivotal for identifying unauthorized access, malware infections, and other security incidents. Key log files include:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): 记录系统范围的消息和活动。
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): 记录认证尝试、成功和失败的登录。
- Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` to filter relevant authentication events.
- **/var/log/boot.log**: 包含系统启动消息。
- **/var/log/maillog** or **/var/log/mail.log**: 记录 email server 活动，对追踪与 email 相关的 services 很有用。
- **/var/log/kern.log**: 存储 kernel 消息，包括错误和警告。
- **/var/log/dmesg**: 保存 device driver 消息。
- **/var/log/faillog**: 记录失败的登录尝试，有助于安全入侵调查。
- **/var/log/cron**: 记录 cron job 执行。
- **/var/log/daemon.log**: 跟踪后台 service 活动。
- **/var/log/btmp**: 记录失败的登录尝试。
- **/var/log/httpd/**: 包含 Apache HTTPD error 和 access logs。
- **/var/log/mysqld.log** or **/var/log/mysql.log**: 记录 MySQL database 活动。
- **/var/log/xferlog**: 记录 FTP 文件传输。
- **/var/log/**: 始终检查这里是否有异常 logs。

> [!TIP]
> Linux system logs and audit subsystems may be disabled or deleted in an intrusion or malware incident. Because logs on Linux systems generally contain some of the most useful information about malicious activities, intruders routinely delete them. Therefore, when examining available log files, it is important to look for gaps or out of order entries that might be an indication of deletion or tampering.

### Journald triage (`journalctl`)

On modern Linux hosts, the **systemd journal** is usually the highest-value source for **service execution**, **auth events**, **package operations**, and **kernel/user-space messages**. During live response, try to preserve both the **persistent** journal (`/var/log/journal/`) and the **runtime** journal (`/run/log/journal/`) because short-lived attacker activity may only exist in the latter.
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
用于分诊的有用 journal 字段包括 `_SYSTEMD_UNIT`、`_EXE`、`_COMM`、`_CMDLINE`、`_UID`、`_GID`、`_PID`、`_BOOT_ID` 和 `MESSAGE`。如果 journald 未配置持久化存储，那么只能在 `/run/log/journal/` 下看到最近的数据。

### Audit framework 分诊 (`auditd`)

如果 `auditd` 已启用，在你需要对文件变更、命令执行、登录活动或包安装进行 **process attribution** 时，优先使用它。
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
当规则带有 keys 部署时，不要直接 grep 原始日志，而是从这些 keys 进行 pivot：
```bash
ausearch --start this-week -k <rule_key> --raw | aureport --file --summary -i
ausearch --start this-week -k <rule_key> --raw | aureport --user --summary -i
```
**Linux 为每个用户维护命令历史记录**，存储在：

- \~/.bash_history
- \~/.zsh_history
- \~/.zsh_sessions/\*
- \~/.python_history
- \~/.\*\_history

此外，`last -Faiwx` 命令会提供用户登录列表。检查其中是否有未知或异常登录。

检查可以授予额外 rprivileges 的文件：

- 查看 `/etc/sudoers`，确认是否有意外授予的用户权限。
- 查看 `/etc/sudoers.d/`，确认是否有意外授予的用户权限。
- 检查 `/etc/groups`，识别任何异常的组成员关系或权限。
- 检查 `/etc/passwd`，识别任何异常的组成员关系或权限。

一些应用程序也会生成自己的日志：

- **SSH**: 检查 _\~/.ssh/authorized_keys_ 和 _\~/.ssh/known_hosts_，查看是否存在未经授权的远程连接。
- **Gnome Desktop**: 查看 _\~/.recently-used.xbel_，了解通过 Gnome 应用程序最近访问过的文件。
- **Firefox/Chrome**: 检查 _\~/.mozilla/firefox_ 或 _\~/.config/google-chrome_ 中的浏览历史和下载记录，查找可疑活动。
- **VIM**: 查看 _\~/.viminfo_，获取使用详情，例如访问过的文件路径和搜索历史。
- **Open Office**: 检查最近的文档访问记录，这可能表明有文件被入侵。
- **FTP/SFTP**: 查看 _\~/.ftp_history_ 或 _\~/.sftp_history_ 中的文件传输日志，可能存在未经授权的传输。
- **MySQL**: 检查 _\~/.mysql_history_ 中执行过的 MySQL 查询，这可能暴露未经授权的数据库活动。
- **Less**: 分析 _\~/.lesshst_ 中的使用历史，包括查看过的文件和执行的命令。
- **Git**: 检查 _\~/.gitconfig_ 和项目中的 _.git/logs_，查看仓库是否有变更。

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) 是一个用纯 Python 3 编写的小型软件，它解析 Linux 日志文件（根据发行版不同，通常是 `/var/log/syslog*` 或 `/var/log/messages*`），用于构建 USB 事件历史表。

了解**所有曾经使用过的 USB** 很有价值；如果你有一份授权 USB 列表，那么它会更有用，可以用来找出“违规事件”（即使用不在该列表中的 USB）。

### Installation
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
更多示例和信息请查看 github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## Review User Accounts and Logon Activities

检查 _**/etc/passwd**_、_**/etc/shadow**_ 和 **security logs**，寻找异常名称，或者与已知未授权事件在时间上接近创建和/或使用的账户。另请检查可能的 sudo 暴力破解攻击。\
此外，检查像 _**/etc/sudoers**_ 和 _**/etc/groups**_ 这样的文件，查看是否向用户授予了意外的权限。\
最后，查找**没有密码**或**容易猜测**密码的账户。

## Examine File System

### Analyzing File System Structures in Malware Investigation

在调查 malware 事件时，file system 的结构是关键信息来源，它可以揭示事件发生的顺序以及 malware 的内容。然而，malware 作者正在开发一些技术来阻碍这种分析，例如修改 file 时间戳，或者避免使用 file system 来存储数据。

为了对抗这些反 forensic 方法，必须：

- **使用诸如** **Autopsy** **之类的工具进行全面的时间线分析**，用于可视化事件时间线，或者使用 **Sleuth Kit** 的 `mactime` 获取详细的时间线数据。
- **调查系统 $PATH 中意外的脚本**，其中可能包含攻击者使用的 shell 或 PHP 脚本。
- **检查 `/dev` 中的异常文件**，因为它传统上包含特殊文件，但也可能存放与 malware 相关的文件。
- **搜索具有隐藏性的文件或目录**，例如 ".. "（点点空格）或 "..^G"（点点控制-G）这类名称，它们可能隐藏恶意内容。
- **使用以下命令识别 setuid root 文件：** `find / -user root -perm -04000 -print` 这会找到具有提升权限的文件，这些权限可能被攻击者滥用。
- **查看 inode 表中的删除时间戳**，以发现大规模文件删除，这可能表明存在 rootkit 或 trojan。
- **检查连续的 inode**，在识别出一个恶意文件后，看看附近是否还有其他恶意文件，因为它们可能被一起放置。
- **检查常见的 binary 目录**（_/bin_、_/sbin_）中最近被修改的文件，因为这些可能已被 malware 篡改。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> 注意，**attacker** 可以**修改** **time** 让**文件看起来** **legitimate**，但他**不能**修改 **inode**。如果你发现某个**file** 显示它是在与同一文件夹中其他文件**相同的时间**被创建和修改的，但 **inode** 却**意外地更大**，那么说明**该文件的 timestamps 被修改了**。

### 基于 Inode 的快速初筛

如果你怀疑有 anti-forensics，尽早运行这些基于 inode 的检查：
```bash
# Filesystem inode pressure (possible inode exhaustion DoS)
df -i

# Identify all names that point to one inode
find / -xdev -inum <inode_number> 2>/dev/null

# Find deleted files still open by running processes
lsof +L1
lsof | grep '(deleted)'
```
当 EXT 文件系统镜像/设备上出现可疑 inode 时，直接检查 inode 元数据：
```bash
sudo debugfs -R "stat <inode_number>" /dev/sdX
```
有用字段：
- **Links**: 如果为 `0`，则当前没有目录项引用该 inode。
- **dtime**: 当 inode 被取消链接时设置的删除时间戳。
- **ctime/mtime**: 有助于将元数据/内容变化与事件时间线进行关联。

### Capabilities、xattrs 和基于 preload 的 userland rootkits

现代 Linux 持久化通常会避免明显的 `setuid` binary，而是滥用 **file capabilities**、**extended attributes** 和 dynamic loader。
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
特别注意从 **writable** 路径引用的库，例如 `/tmp`、`/dev/shm`、`/var/tmp`，或 `/usr/local/lib` 下的异常位置。还要检查正常 package ownership 之外带有 capability 的 binaries，并将它们与 package verification 结果（`rpm -Va`、`dpkg --verify`、`debsums`）关联起来。

## 比较不同 filesystem 版本的 files

### filesystem version 比较摘要

为了比较 filesystem versions 并定位 changes，我们使用简化的 `git diff` commands：

- **要查找 new files**，比较两个 directories：
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **对于修改后的内容**, 列出变更，同时忽略特定行:
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **检测已删除文件**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) 可帮助缩小范围到特定变更，例如新增 (`A`)、删除 (`D`) 或修改 (`M`) 的文件。
- `A`: 新增文件
- `C`: 复制的文件
- `D`: 删除的文件
- `M`: 修改的文件
- `R`: 重命名的文件
- `T`: 类型变更（例如，file 到 symlink）
- `U`: 未合并文件
- `X`: 未知文件
- `B`: 损坏的文件

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)
- [Say hi to Pike!](https://www.synacktiv.com/en/publications/say-hi-to-pike.html)
- [strace](https://strace.io/)
- [SQLite FTS5 Extension](https://www.sqlite.org/fts5.html)

{{#include ../../banners/hacktricks-training.md}}
