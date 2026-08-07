# 사용자 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

사용자 네임스페이스는 커널이 네임스페이스 내부에서 보이는 사용자 및 그룹 ID를 네임스페이스 외부의 다른 ID에 매핑하도록 하여 해당 ID의 의미를 변경합니다. 이는 classic containers의 가장 큰 역사적 문제를 직접 해결하기 때문에 가장 중요한 modern container protections 중 하나입니다. **container 내부의 root가 host의 root와 지나치게 가까운 권한을 갖고 있었다는 문제**입니다.

사용자 네임스페이스를 사용하면 프로세스가 container 내부에서 UID 0으로 실행되더라도 host에서는 권한이 없는 UID 범위에 해당할 수 있습니다. 즉, 프로세스는 많은 in-container 작업에서 root처럼 동작하면서도 host의 관점에서는 훨씬 적은 권한만 가질 수 있습니다. 이것이 모든 container security 문제를 해결하는 것은 아니지만, container compromise의 결과를 크게 바꿉니다.

## 동작

사용자 네임스페이스에는 `/proc/self/uid_map` 및 `/proc/self/gid_map`과 같은 mapping files가 있으며, 이 파일은 네임스페이스 ID가 parent ID로 어떻게 변환되는지 설명합니다. 네임스페이스 내부의 root가 권한이 없는 host UID에 매핑되면, 실제 host root 권한이 필요한 작업도 동일한 영향력을 갖지 못합니다. 이것이 사용자 네임스페이스가 **rootless containers**의 핵심이며, 과거의 rootful container defaults와 보다 modern least-privilege designs 사이에서 가장 큰 차이 중 하나인 이유입니다.

핵심은 미묘하지만 매우 중요합니다. container 내부의 root가 제거되는 것이 아니라 **변환되는 것**입니다. 프로세스는 여전히 로컬에서 root와 유사한 환경을 경험하지만, host는 해당 프로세스를 full root로 취급해서는 안 됩니다.

## 실습

수동 테스트는 다음과 같습니다:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
이렇게 하면 현재 사용자가 namespace 내부에서는 root로 보이지만, 외부의 host에서는 여전히 root가 아닌 상태로 유지됩니다. 이는 user namespaces가 왜 매우 유용한지 이해하기 위한 가장 간단하면서도 훌륭한 데모 중 하나입니다.

containers에서는 다음과 같이 표시되는 mapping을 비교할 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
정확한 출력은 engine이 user namespace remapping을 사용하는지 또는 보다 전통적인 rootful 구성을 사용하는지에 따라 달라집니다.

다음 명령으로 host 측에서도 mapping을 읽을 수 있습니다:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## Runtime 사용

Rootless Podman은 user namespace가 first-class security mechanism으로 취급되는 가장 명확한 사례 중 하나입니다. Rootless Docker 역시 user namespace에 의존합니다. Docker의 userns-remap 지원은 rootful daemon deployment에서도 안전성을 향상시키지만, 역사적으로 많은 deployment에서는 호환성 문제로 비활성화된 상태로 두었습니다. Kubernetes의 user namespace 지원은 개선되었지만, 도입 여부와 기본값은 runtime, distro, cluster policy에 따라 다릅니다. Incus/LXC 시스템 역시 UID/GID shifting 및 idmapping 개념에 크게 의존합니다.

일반적인 추세는 분명합니다. user namespace를 진지하게 사용하는 환경은 그렇지 않은 환경보다 "container root가 실제로 무엇을 의미하는가?"라는 질문에 대체로 더 나은 답을 제공합니다.

## Advanced Mapping Details

unprivileged process가 `uid_map` 또는 `gid_map`에 쓸 때 kernel은 privileged parent namespace writer에 적용하는 것보다 더 엄격한 규칙을 적용합니다. 허용되는 mapping은 제한적이며, `gid_map`의 경우 writer는 일반적으로 먼저 `setgroups(2)`를 비활성화해야 합니다:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
이 세부 사항은 user-namespace 설정이 rootless 실험에서 때때로 실패하는 이유와, runtime에 UID/GID 위임을 처리하는 신중한 helper 로직이 필요한 이유를 설명하기 때문에 중요합니다.

또 다른 advanced feature는 **ID-mapped mount**입니다. 디스크상의 ownership을 변경하는 대신, ID-mapped mount는 mount에 user-namespace mapping을 적용하여 해당 mount view를 통해 ownership이 변환되어 보이도록 합니다. 이는 rootless 및 modern runtime 설정에서 특히 중요합니다. recursive `chown` 작업 없이도 공유된 host 경로를 사용할 수 있게 해주기 때문입니다. Security 측면에서 이 feature는 underlying filesystem metadata를 다시 쓰지 않더라도 namespace 내부에서 bind mount가 얼마나 writable하게 보이는지를 변경합니다.

마지막으로, process가 새로운 user namespace를 생성하거나 진입할 때 **해당 namespace 내부에서** 전체 capability set을 받는다는 점을 기억해야 합니다. 그렇다고 갑자기 host-global power를 얻는 것은 아닙니다. 이는 namespace model과 다른 protections가 허용하는 범위에서만 해당 capabilities를 사용할 수 있다는 의미입니다. 이것이 `unshare -U`를 사용하면 host root boundary를 직접 없애지 않고도 mount 또는 namespace-local privileged operations가 갑자기 가능해질 수 있는 이유입니다.

## Misconfigurations

가장 큰 weakness는 user namespaces를 사용할 수 있는 환경에서 이를 사용하지 않는 것입니다. Container root가 host root에 너무 직접적으로 매핑되면 writable host mounts와 privileged kernel operations가 훨씬 더 위험해집니다. 또 다른 문제는 이러한 변경이 trust boundary에 얼마나 큰 영향을 주는지 인식하지 못한 채, compatibility를 위해 host user namespace sharing을 강제하거나 remapping을 비활성화하는 것입니다.

User namespaces는 model의 나머지 부분과 함께 고려해야 합니다. User namespaces가 active 상태여도, 광범위한 runtime API exposure나 매우 취약한 runtime configuration으로 인해 다른 경로를 통한 privilege escalation이 여전히 가능할 수 있습니다. 하지만 user namespaces가 없으면 많은 기존 breakout class를 훨씬 쉽게 exploit할 수 있습니다.

## Abuse

Container가 user namespace separation 없이 rootful인 경우, writable host bind mount는 process가 실제로 host root로 write할 수 있으므로 훨씬 더 위험해집니다. Dangerous capabilities 역시 더 큰 의미를 갖습니다. Translation boundary가 거의 존재하지 않기 때문에 attacker는 더 이상 그 경계와 맞서 싸우는 데 많은 노력을 들일 필요가 없습니다.

Container breakout path를 평가할 때는 user namespace의 존재 여부를 초기에 확인해야 합니다. 이것이 모든 질문에 답해주지는 않지만, "root in container"가 host에 직접적인 relevance를 갖는지 즉시 보여줍니다.

가장 practical한 abuse pattern은 mapping을 확인한 다음, host-mounted content가 host-relevant privileges로 writable한지 즉시 테스트하는 것입니다:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
파일이 실제 host root 권한으로 생성되면 해당 경로에 대한 user namespace 격리는 사실상 사라집니다. 이 시점부터는 고전적인 host 파일 악용이 현실적인 위협이 됩니다:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
실제 assessment에서 더 안전하게 확인하려면 중요한 파일을 수정하는 대신 무해한 marker를 작성합니다:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
이러한 검사가 중요한 이유는 다음과 같은 실제 질문에 빠르게 답해 주기 때문입니다. 이 container의 root가 host의 root에 충분히 가깝게 매핑되어 있어, 쓰기 가능한 host mount가 즉시 host compromise 경로가 되는가?

### 전체 예시: Namespace-Local Capabilities 되찾기

seccomp이 `unshare`를 허용하고 환경에서 새로운 user namespace 생성을 허용한다면, 프로세스는 해당 새로운 namespace 내부에서 전체 capability set을 되찾을 수 있습니다:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
이 자체만으로는 host escape가 아닙니다. 중요한 이유는 user namespaces가 namespace 내부에서만 유효한 privileged actions를 다시 활성화할 수 있으며, 이러한 actions가 이후 취약한 mount, 취약한 kernel 또는 잘못 노출된 runtime surface와 결합할 수 있기 때문입니다.

## Checks

이 명령어들은 이 페이지에서 가장 중요한 질문에 답하기 위한 것입니다. 이 container 내부의 root는 host에서 무엇으로 매핑되는가?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
여기서 중요한 점은 다음과 같습니다:

- 프로세스가 UID 0이고 maps에 host-root에 대한 직접 매핑 또는 매우 가까운 매핑이 표시된다면, 해당 container는 훨씬 더 위험합니다.
- root가 권한이 없는 host 범위에 매핑된다면, 이는 훨씬 더 안전한 baseline이며 일반적으로 실제 user namespace isolation을 나타냅니다.
- 매핑 파일은 `id`만 사용하는 것보다 더 유용합니다. `id`는 namespace-local identity만 표시하기 때문입니다.

workload가 UID 0으로 실행되고 매핑에서 이것이 host root에 가깝게 대응하는 것으로 나타난다면, container의 나머지 privileges를 훨씬 더 엄격하게 해석해야 합니다.

{{#include ../../../../../banners/hacktricks-training.md}}
