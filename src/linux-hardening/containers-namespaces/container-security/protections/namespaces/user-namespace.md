# User Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

User namespace는 커널이 namespace 내부에서 보이는 사용자 및 그룹 ID를 외부의 다른 ID에 매핑할 수 있도록 하여 사용자 및 그룹 ID의 의미를 변경합니다. 이는 classic containers의 가장 큰 역사적 문제를 직접 해결하기 때문에 가장 중요한 현대 container 보호 기능 중 하나입니다. **container 내부의 root가 host의 root와 지나치게 가까웠다**는 문제입니다.

User namespaces를 사용하면 프로세스가 container 내부에서 UID 0으로 실행되면서도 host에서는 권한이 없는 UID 범위에 대응할 수 있습니다. 즉, 프로세스는 많은 container 내부 작업에서 root처럼 동작하면서도 host 관점에서는 훨씬 적은 권한만 가질 수 있습니다. 이것이 모든 container security 문제를 해결하는 것은 아니지만, container compromise의 결과를 크게 바꿉니다.

## 동작

User namespace에는 `/proc/self/uid_map` 및 `/proc/self/gid_map`과 같은 mapping file이 있으며, namespace ID가 parent ID로 어떻게 변환되는지 설명합니다. namespace 내부의 root가 권한이 없는 host UID에 매핑되면, 실제 host root 권한이 필요한 작업도 동일한 영향력을 발휘하지 못합니다. 이것이 user namespaces가 **rootless containers**의 핵심이며, 과거의 rootful container 기본 설정과 더욱 현대적인 least-privilege 설계 사이에서 가장 큰 차이 중 하나인 이유입니다.

핵심은 미묘하지만 매우 중요합니다. container 내부의 root가 제거되는 것이 아니라 **변환**되는 것입니다. 프로세스는 여전히 로컬에서 root와 유사한 환경을 경험하지만, host는 이를 완전한 root로 취급해서는 안 됩니다.

## 실습

수동 테스트는 다음과 같습니다:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
이렇게 하면 현재 사용자가 namespace 내부에서는 root로 보이지만, namespace 외부의 host에서는 여전히 root가 아닙니다. 이는 user namespace가 왜 그토록 중요한지 이해하기 위한 가장 간단하고 좋은 예시 중 하나입니다.

containers에서는 다음과 같이 표시되는 mapping을 비교할 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
정확한 출력은 엔진이 user namespace remapping을 사용하는지, 아니면 보다 전통적인 rootful configuration을 사용하는지에 따라 달라집니다.

호스트 측에서는 다음을 사용하여 매핑을 확인할 수도 있습니다:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime 사용

Rootless Podman은 user namespace가 핵심 보안 메커니즘으로 취급되는 가장 명확한 사례 중 하나입니다. Rootless Docker도 user namespace에 의존합니다. Docker의 userns-remap 지원은 rootful daemon 배포 환경의 안전성도 향상하지만, 역사적으로 많은 배포 환경에서는 호환성 문제로 비활성화된 상태로 두었습니다. Kubernetes의 user namespace 지원은 개선되었지만, 실제 도입과 기본 설정은 runtime, distro, cluster policy에 따라 다릅니다. Incus/LXC 시스템 역시 UID/GID shifting 및 idmapping 개념에 크게 의존합니다.

전반적인 추세는 분명합니다. user namespace를 진지하게 사용하는 환경은 그렇지 않은 환경보다 "container root가 실제로 무엇을 의미하는가?"라는 질문에 대체로 더 나은 답을 제공합니다.

## Advanced Mapping 세부 사항

unprivileged process가 `uid_map` 또는 `gid_map`에 기록할 때 kernel은 privileged parent namespace writer에 적용하는 것보다 더 엄격한 규칙을 적용합니다. 허용되는 mapping은 제한적이며, `gid_map`의 경우 writer는 일반적으로 먼저 `setgroups(2)`를 비활성화해야 합니다:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
이 세부 사항은 user-namespace 설정이 rootless 실험에서 때때로 실패하는 이유와, runtime에 UID/GID delegation을 처리하는 신중한 helper logic가 필요한 이유를 설명하기 때문에 중요합니다.

또 다른 advanced feature는 **ID-mapped mount**입니다. 디스크상의 ownership을 변경하는 대신, ID-mapped mount는 mount에 user-namespace mapping을 적용하여 해당 mount view를 통해 ownership이 변환되어 보이도록 합니다. 이는 recursive `chown` 작업 없이도 공유된 host path를 사용할 수 있도록 해 주기 때문에 rootless 및 modern runtime 설정에서 특히 중요합니다. Security 측면에서 이 feature는 underlying filesystem metadata를 다시 작성하지 않으면서도 namespace 내부에서 bind mount가 얼마나 writable한지에 대한 표시를 변경합니다.

마지막으로, process가 새로운 user namespace를 생성하거나 진입하면 **해당 namespace 내부에서** full capability set을 받는다는 점을 기억해야 합니다. 그렇다고 갑자기 host-global power를 얻는 것은 아닙니다. 이는 namespace model과 기타 protections가 허용하는 범위에서만 해당 capabilities를 사용할 수 있다는 뜻입니다. 이것이 `unshare -U`를 사용하면 host root boundary를 직접 없애지 않고도 mounting 또는 namespace-local privileged operations가 갑자기 가능해지는 이유입니다.

## Misconfigurations

가장 큰 weakness는 user namespaces를 사용할 수 있는 환경에서 이를 사용하지 않는 것입니다. container root가 host root에 너무 직접적으로 mapping되면 writable host mounts와 privileged kernel operations가 훨씬 더 위험해집니다. 또 다른 문제는 이러한 변화가 trust boundary에 얼마나 큰 영향을 주는지 인식하지 못한 채 compatibility를 위해 host user namespace sharing을 강제하거나 remapping을 비활성화하는 것입니다.

user namespaces는 나머지 model과 함께 고려해야 합니다. user namespaces가 active 상태이더라도, broad runtime API exposure나 매우 약한 runtime configuration이 있으면 다른 경로를 통한 privilege escalation이 여전히 가능할 수 있습니다. 하지만 user namespaces가 없으면 많은 오래된 breakout class를 훨씬 쉽게 exploit할 수 있습니다.

## Abuse

user namespace separation 없이 container가 rootful인 경우, process가 실제로 host root 권한으로 write할 수 있기 때문에 writable host bind mount는 훨씬 더 위험해집니다. Dangerous capabilities 역시 더욱 중요한 의미를 갖습니다. translation boundary가 거의 존재하지 않으므로 attacker는 더 이상 그 boundary를 상대로 어렵게 대응할 필요가 없습니다.

container breakout path를 평가할 때는 user namespace의 존재 여부를 초기에 확인해야 합니다. 이것이 모든 질문에 답해 주지는 않지만, `"root in container"`가 host와 직접적인 관련성을 갖는지 즉시 보여 줍니다.

가장 practical한 abuse pattern은 mapping을 확인한 다음, host-mounted content가 host-relevant privileges로 writable한지 즉시 테스트하는 것입니다:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
파일이 실제 호스트 root 권한으로 생성되면 해당 경로에 대한 user namespace 격리는 사실상 사라집니다. 이 시점부터는 기존의 호스트 파일 악용이 현실적인 공격 벡터가 됩니다:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
실제 assessment에서 더 안전하게 확인하려면 중요한 파일을 수정하는 대신 무해한 marker를 작성합니다:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
이러한 검사가 중요한 이유는 실제 질문에 빠르게 답해 주기 때문입니다. 즉, 이 컨테이너의 root가 host의 root와 충분히 밀접하게 매핑되어 있어 쓰기 가능한 host mount가 즉시 host compromise 경로가 되는지 확인할 수 있습니다.

### 전체 예시: Namespace-Local Capabilities 되찾기

seccomp가 `unshare`를 허용하고 환경에서 새로운 user namespace를 만들 수 있다면, 프로세스는 해당 새 namespace 내부에서 전체 capability set을 되찾을 수 있습니다.
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
이 자체로 host escape는 아닙니다. 중요한 이유는 user namespaces가 namespace 내부에서만 유효한 privileged action을 다시 활성화할 수 있으며, 이러한 작업이 이후 weak mount, 취약한 kernel 또는 부적절하게 노출된 runtime surface와 결합될 수 있기 때문입니다.

## 확인

이 명령어들은 이 페이지에서 가장 중요한 질문에 답하기 위한 것입니다. 이 container 내부의 root가 host에서 무엇으로 매핑되는가?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
여기서 중요한 점은 다음과 같습니다.

- 프로세스가 UID 0이고 maps에 host-root에 직접 매핑되거나 매우 가깝게 매핑된 것으로 나타나면, 해당 컨테이너는 훨씬 더 위험합니다.
- root가 권한이 없는 호스트 범위에 매핑된다면, 이는 훨씬 더 안전한 기준이며 일반적으로 실제 user namespace 격리가 적용되었음을 의미합니다.
- 매핑 파일은 `id`만 사용하는 것보다 더 유용합니다. `id`는 namespace 내 로컬 identity만 보여 주기 때문입니다.

workload가 UID 0으로 실행되고 매핑에서 이것이 host root에 가깝게 대응하는 것으로 나타난다면, 컨테이너의 나머지 권한을 훨씬 더 엄격하게 해석해야 합니다.
{{#include ../../../../../banners/hacktricks-training.md}}
