# Linux Forensics

{{#include ../../banners/hacktricks-training.md}}

## Initial Information Gathering

### Basic Information

首先，建议准备一个装有**已知良好二进制文件和库**的 **USB**（你可以直接获取 ubuntu 并复制 _/bin_、_/sbin_、_/lib,_ 和 _/lib64_ 这些文件夹），然后挂载 USB，并修改环境变量以使用这些二进制文件：
```bash
export PATH=/mnt/usb/bin:/mnt/usb/sbin
export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
```
一旦你将系统配置为使用良好且已知的 binaries，你就可以开始**提取一些基本信息**：
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

在获取基本信息时，你应该检查一些异常情况，例如：

- **Root 进程** 通常运行在较低的 PID 上，所以如果你发现一个 root 进程的 PID 很大，可能值得怀疑
- 检查 `/etc/passwd` 中**没有 shell 的用户**的**已注册登录**信息
- 检查 `/etc/shadow` 中**没有 shell 的用户**的**密码哈希**

### 内存转储

要获取正在运行系统的内存，建议使用 [**LiME**](https://github.com/504ensicsLabs/LiME)。\
要**编译**它，你需要使用受害机器正在使用的**相同 kernel**。

> [!TIP]
> 记住，你**不能**在受害机器上安装 LiME 或任何其他东西，因为这会对它进行多项更改

因此，如果你有一个相同版本的 Ubuntu，你可以使用 `apt-get install lime-forensics-dkms`\
在其他情况下，你需要从 github 下载 [**LiME**](https://github.com/504ensicsLabs/LiME)，并使用正确的 kernel headers 对其进行编译。要**获取受害机器的精确 kernel headers**，你只需将目录 `/lib/modules/<kernel version>` **复制**到你的机器，然后使用它们来**编译** LiME：
```bash
make -C /lib/modules/<kernel version>/build M=$PWD
sudo insmod lime.ko "path=/home/sansforensics/Desktop/mem_dump.bin format=lime"
```
LiME supports 3 **formats**:

- Raw (every segment concatenated together)
- Padded (same as raw, but with zeroes in right bits)
- Lime (recommended format with metadata

LiME 也可以用于**通过网络发送 dump**，而不是将其存储在系统上，例如：`path=tcp:4444`

### Disk Imaging

#### Shutting down

首先，你需要**关闭系统**。这并不总是可行，因为有时系统可能是公司的生产服务器，公司无法承受关机。\
有 **2 种方式**可以关闭系统：**正常关机** 和 **"plug the plug" shutdown**。第一种会让**进程**像往常一样**终止**，并使**文件系统**得到**同步**，但它也会让可能存在的**malware**有机会**销毁证据**。 "pull the plug" 方法可能会带来**一些信息丢失**（不过由于我们已经获取了内存镜像，信息不会丢失太多），并且**malware**不会有任何机会对此做什么。因此，如果你**怀疑**可能存在**malware**，那就只需在系统上执行 **`sync`** **命令**，然后拔掉电源。

#### Taking an image of the disk

需要注意的是，**在将你的电脑连接到与案件相关的任何设备之前**，你必须确认它将以**只读**方式**挂载**，以避免修改任何信息。
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

Linux 提供了用于确保系统组件完整性的工具，这对于发现可能有问题的文件至关重要。

- **基于 RedHat 的系统**: 使用 `rpm -Va` 进行全面检查。
- **基于 Debian 的系统**: 先使用 `dpkg --verify` 进行初步验证，然后执行 `debsums | grep -v "OK$"`（先通过 `apt-get install debsums` 安装 `debsums`）来识别任何问题。

### Malware/Rootkit Detectors

阅读以下页面，了解可用于查找 malware 的工具：


{{#ref}}
malware-analysis.md
{{#endref}}

## 搜索已安装程序

为了在 Debian 和 RedHat 系统上有效搜索已安装程序，可以结合系统日志、数据库以及对常见目录的手动检查。

- 对于 Debian，检查 _**`/var/lib/dpkg/status`**_ 和 _**`/var/log/dpkg.log`**_，通过使用 `grep` 过滤特定信息来获取包安装详情。
- RedHat 用户可以使用 `rpm -qa --root=/mntpath/var/lib/rpm` 查询 RPM 数据库以列出已安装的软件包。

要找出手动安装或在这些 package manager 之外安装的软件，请查看 _**`/usr/local`**_、_**`/opt`**_、_**`/usr/sbin`**_、_**`/usr/bin`**_、_**`/bin`**_ 和 _**`/sbin`**_ 等目录。将目录列表与系统特定命令结合使用，以识别不属于已知软件包的可执行文件，从而更全面地搜索所有已安装程序。
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
## 恢复已删除的正在运行二进制文件

设想一个进程是从 /tmp/exec 执行的，随后被删除。可以将其提取出来
```bash
cd /proc/3746/ #PID with the exec file deleted
head -1 maps #Get address of the file. It was 08048000-08049000
dd if=mem bs=1 skip=08048000 count=1000 of=/tmp/exec2 #Recorver it
```
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
#### Hunt: 通过 0anacron 和可疑 stub 滥用 Cron/Anacron
攻击者经常编辑位于每个 /etc/cron.*/ 目录下的 0anacron stub，以确保周期性执行。
```bash
# List 0anacron files and their timestamps/sizes
for d in /etc/cron.*; do [ -f "$d/0anacron" ] && stat -c '%n %y %s' "$d/0anacron"; done

# Look for obvious execution of shells or downloaders embedded in cron stubs
grep -R --line-number -E 'curl|wget|/bin/sh|python|bash -c' /etc/cron.*/* 2>/dev/null
```
#### Hunt: SSH 加固回滚和后门 shells
对 sshd_config 和系统账户 shells 的更改是 post‑exploitation 后为保留访问权限而常见的。
```bash
# Root login enablement (flag "yes" or lax values)
grep -E '^\s*PermitRootLogin' /etc/ssh/sshd_config

# System accounts with interactive shells (e.g., games → /bin/sh)
awk -F: '($7 ~ /bin\/(sh|bash|zsh)/ && $1 ~ /^(games|lp|sync|shutdown|halt|mail|operator)$/) {print}' /etc/passwd
```
#### Hunt: Cloud C2 markers (Dropbox/Cloudflare Tunnel)
- Dropbox API beacons typically use api.dropboxapi.com or content.dropboxapi.com over HTTPS with Authorization: Bearer tokens.
- Hunt in proxy/Zeek/NetFlow for unexpected Dropbox egress from servers.
- Cloudflare Tunnel (`cloudflared`) provides backup C2 over outbound 443.
```bash
ps aux | grep -E '[c]loudflared|trycloudflare'
systemctl list-units | grep -i cloudflared
```
### Services

malware 可能作为 service 安装的路径：

- **/etc/inittab**: 调用初始化脚本，如 rc.sysinit，并进一步指向启动脚本。
- **/etc/rc.d/** 和 **/etc/rc.boot/**: 包含 service 启动脚本，后者可在较旧的 Linux 版本中找到。
- **/etc/init.d/**: 在某些 Linux 版本（如 Debian）中用于存放启动脚本。
- service 也可能通过 **/etc/inetd.conf** 或 **/etc/xinetd/** 激活，具体取决于 Linux 变体。
- **/etc/systemd/system**: system 和 service manager 脚本的目录。
- **/etc/systemd/system/multi-user.target.wants/**: 包含应在 multi-user runlevel 中启动的 service 链接。
- **/usr/local/etc/rc.d/**: 用于自定义或第三方 service。
- **\~/.config/autostart/**: 用于用户特定的自动启动应用程序，可能是针对用户的 malware 的隐藏位置。
- **/lib/systemd/system/**: 已安装软件包提供的系统范围默认 unit 文件。

#### Hunt: systemd timers and transient units

Systemd persistence 不仅限于 `.service` 文件。请检查 `.timer` units、用户级 units，以及运行时创建的 **transient units**。
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

- **/lib/modules/$(uname -r)**: 保存当前运行的 kernel version 的 modules。
- **/etc/modprobe.d**: 包含用于控制 module loading 的配置文件。
- **/etc/modprobe** and **/etc/modprobe.conf**: 用于全局 module settings 的文件。

### Other Autostart Locations

Linux employs various files for automatically executing programs upon user login, potentially harboring malware:

- **/etc/profile.d/**\*, **/etc/profile**, and **/etc/bash.bashrc**: 在任何用户 login 时执行。
- **\~/.bashrc**, **\~/.bash_profile**, **\~/.profile**, and **\~/.config/autostart**: 用户特定文件，在其 login 时运行。
- **/etc/rc.local**: 在所有 system services 启动后运行，标志着向 multiuser environment 过渡的结束。

## Examine Logs

Linux systems track user activities and system events through various log files. These logs are pivotal for identifying unauthorized access, malware infections, and other security incidents. Key log files include:

- **/var/log/syslog** (Debian) or **/var/log/messages** (RedHat): 记录 system-wide messages and activities。
- **/var/log/auth.log** (Debian) or **/var/log/secure** (RedHat): 记录 authentication attempts、成功和失败的 logins。
- Use `grep -iE "session opened for|accepted password|new session|not in sudoers" /var/log/auth.log` to filter relevant authentication events.
- **/var/log/boot.log**: 包含 system startup messages。
- **/var/log/maillog** or **/var/log/mail.log**: 记录 email server activities，适用于跟踪 email-related services。
- **/var/log/kern.log**: 存储 kernel messages，包括 errors 和 warnings。
- **/var/log/dmesg**: 保存 device driver messages。
- **/var/log/faillog**: 记录 failed login attempts，有助于 security breach investigations。
- **/var/log/cron**: 记录 cron job executions。
- **/var/log/daemon.log**: 跟踪 background service activities。
- **/var/log/btmp**: 记录 failed login attempts。
- **/var/log/httpd/**: 包含 Apache HTTPD error and access logs。
- **/var/log/mysqld.log** or **/var/log/mysql.log**: 记录 MySQL database activities。
- **/var/log/xferlog**: 记录 FTP file transfers。
- **/var/log/**: 始终检查这里是否有 unexpected logs。

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
用于分诊的有用 journal 字段包括 `_SYSTEMD_UNIT`、`_EXE`、`_COMM`、`_CMDLINE`、`_UID`、`_GID`、`_PID`、`_BOOT_ID` 和 `MESSAGE`。如果 journald 未配置持久化存储，则只会在 `/run/log/journal/` 下保留最近的数据。

### Audit framework 分诊 (`auditd`)

如果启用了 `auditd`，当你需要对文件更改、命令执行、登录活动或软件包安装进行 **process attribution** 时，优先使用它。
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
当规则与密钥一起部署时，应从这些规则出发进行 pivot，而不是直接 grep 原始日志：
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

检查可能授予额外 rprivileges 的文件：

- 查看 `/etc/sudoers`，查找是否有意外授予的用户权限。
- 查看 `/etc/sudoers.d/`，查找是否有意外授予的用户权限。
- 检查 `/etc/groups`，识别任何异常的组成员关系或权限。
- 检查 `/etc/passwd`，识别任何异常的组成员关系或权限。

一些应用也会生成自己的日志：

- **SSH**: 检查 _\~/.ssh/authorized_keys_ 和 _\~/.ssh/known_hosts_，查找未经授权的远程连接。
- **Gnome Desktop**: 查看 _\~/.recently-used.xbel_，了解通过 Gnome 应用最近访问的文件。
- **Firefox/Chrome**: 检查 _\~/.mozilla/firefox_ 或 _\~/.config/google-chrome_ 中的浏览器历史记录和下载内容，查找可疑活动。
- **VIM**: 查看 _\~/.viminfo_，了解使用详情，例如访问过的文件路径和搜索历史。
- **Open Office**: 检查最近打开的文档，这可能表明文件已被入侵。
- **FTP/SFTP**: 查看 _\~/.ftp_history_ 或 _\~/.sftp_history_ 中的文件传输日志，这些传输可能未经授权。
- **MySQL**: 调查 _\~/.mysql_history_ 中执行过的 MySQL 查询，可能会暴露未经授权的数据库活动。
- **Less**: 分析 _\~/.lesshst_ 中的使用历史，包括查看过的文件和执行的命令。
- **Git**: 检查 _\~/.gitconfig_ 和项目 _.git/logs_ 中对仓库的更改。

### USB Logs

[**usbrip**](https://github.com/snovvcrash/usbrip) 是一个用纯 Python 3 编写的小型软件，它解析 Linux 日志文件（根据发行版不同为 `/var/log/syslog*` 或 `/var/log/messages*`），用于构建 USB 事件历史表。

了解**所有曾被使用过的 USB** 很有意义；如果你有一份授权 USB 列表，那么找出“违规事件”（使用不在该列表中的 USB）会更有用。

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
更多示例和信息见 github: [https://github.com/snovvcrash/usbrip](https://github.com/snovvcrash/usbrip)

## 检查 User Accounts 和 Logon Activities

检查 _**/etc/passwd**_、_**/etc/shadow**_ 和 **security logs**，查看是否有异常名称，或在已知未授权事件前后紧密创建和/或使用的账户。还要检查可能的 sudo brute-force attacks。\
另外，检查 _**/etc/sudoers**_ 和 _**/etc/groups**_ 等文件，查看是否给用户授予了意外的权限。\
最后，查找 **没有密码** 或 **容易猜测** 密码的账户。

## 检查 File System

### Analyzing File System Structures in Malware Investigation

在调查 malware 事件时，file system 的结构是一个至关重要的信息来源，它能揭示事件发生的顺序以及 malware 的内容。然而，malware 作者正在开发一些技术来阻碍这种分析，例如修改 file timestamps 或避免使用 file system 进行数据存储。

为应对这些 anti-forensic 方法，需要：

- **使用 Autopsy 等工具进行全面的 timeline analysis**，用于可视化 event timelines；或者使用 **Sleuth Kit 的** `mactime` 获取详细的 timeline 数据。
- **检查系统 $PATH 中是否存在异常脚本**，其中可能包括攻击者使用的 shell 或 PHP 脚本。
- **检查 `/dev` 中是否存在非典型文件**，因为它通常只包含特殊文件，但也可能容纳与 malware 相关的文件。
- **搜索隐藏文件或目录**，例如名字为 ".. "（点点空格）或 "..^G"（点点 Ctrl-G）的项，这些可能会隐藏恶意内容。
- **使用命令识别 setuid root 文件**：`find / -user root -perm -04000 -print` 这会找出具有提升权限的文件，攻击者可能会滥用它们。
- **检查 inode 表中的删除时间戳**，以发现批量删除文件的情况，这可能表明存在 rootkits 或 trojans。
- **在识别出一个可疑文件后，检查连续的 inodes**，寻找附近的恶意文件，因为它们可能是一起放置的。
- **检查常见 binary directories**（_/bin_、_/sbin_）中最近被修改的文件，因为这些文件可能已被 malware 篡改。
````bash
# List recent files in a directory:
ls -laR --sort=time /bin```

# Sort files in a directory by inode:
ls -lai /bin | sort -n```
````
> [!TIP]
> 注意，**attacker** 可以**修改** **time** 让**files appear** 看起来**合法**，但他**无法**修改 **inode**。如果你发现某个**file** 显示它的创建和修改时间与同一文件夹中的其他文件**相同**，但 **inode** 却**异常更大**，那么该**file** 的**timestamps** 被**修改**了。

### 以 inode 为重点的快速初步检查

如果你怀疑存在 anti-forensics，尽早运行这些以 inode 为重点的检查：
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
Useful fields:
- **Links**: if `0`, no directory entry currently references the inode.
- **dtime**: deletion timestamp set when the inode was unlinked.
- **ctime/mtime**: helps correlate metadata/content changes with incident timeline.

### Capabilities, xattrs, and preload-based userland rootkits

Modern Linux persistence often avoids obvious `setuid` binaries and instead abuses **file capabilities**, **extended attributes**, and the dynamic loader.
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

## Compare files of different filesystem versions

### Filesystem Version Comparison Summary

为了比较 filesystem versions 并找出变化，我们使用简化的 `git diff` 命令：

- **要查找新文件**，比较两个目录：
```bash
git diff --no-index --diff-filter=A path/to/old_version/ path/to/new_version/
```
- **对于已修改的内容**，请列出更改，同时忽略特定行：
```bash
git diff --no-index --diff-filter=M path/to/old_version/ path/to/new_version/ | grep -E "^\+" | grep -v "Installed-Time"
```
- **要检测已删除的文件**:
```bash
git diff --no-index --diff-filter=D path/to/old_version/ path/to/new_version/
```
- **Filter options** (`--diff-filter`) 有助于缩小范围，定位特定更改，例如新增 (`A`)、删除 (`D`) 或修改 (`M`) 的文件。
- `A`: 新增文件
- `C`: 复制的文件
- `D`: 删除的文件
- `M`: 修改的文件
- `R`: 重命名的文件
- `T`: 类型变更（例如，文件变为 symlink）
- `U`: 未合并文件
- `X`: 未知文件
- `B`: 损坏文件

## References

- [https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf](https://cdn.ttgtmedia.com/rms/security/Malware%20Forensics%20Field%20Guide%20for%20Linux%20Systems_Ch3.pdf)
- [https://www.plesk.com/blog/featured/linux-logs-explained/](https://www.plesk.com/blog/featured/linux-logs-explained/)
- [https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203](https://git-scm.com/docs/git-diff#Documentation/git-diff.txt---diff-filterACDMRTUXB82308203)
- **Book: Malware Forensics Field Guide for Linux Systems: Digital Forensics Field Guides**

- [Red Canary – Patching for persistence: How DripDropper Linux malware moves through the cloud](https://redcanary.com/blog/threat-intelligence/dripdropper-linux-malware/)
- [Forensic Analysis of Linux Journals](https://stuxnet999.github.io/dfir/linux-journal-forensics/)
- [Red Hat Enterprise Linux 9 - Auditing the system](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/security_hardening/auditing-the-system_security-hardening)

{{#include ../../banners/hacktricks-training.md}}
