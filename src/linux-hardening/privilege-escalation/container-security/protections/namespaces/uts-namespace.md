# UTS Namespace

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

UTS namespace는 프로세스가 보는 **hostname**과 **NIS domain name**을 격리합니다. 언뜻 보기에는 mount, PID, or user namespaces에 비해 사소해 보일 수 있지만, 이것은 container가 자체 호스트인 것처럼 보이게 하는 요소의 일부입니다. 네임스페이스 내부에서 workload는 머신 전체(global)가 아닌 해당 네임스페이스에 로컬한 hostname을 보고 때로는 변경할 수 있습니다.

단독으로는 보통 breakout 이야기의 핵심이 되지는 않습니다. 그러나 host UTS namespace가 공유되면, 충분한 권한을 가진 프로세스가 host identity 관련 설정에 영향을 줄 수 있으며, 이는 운영상 중요할 수 있고 때때로 보안 측면에서도 문제를 일으킬 수 있습니다.

## 실습

You can create a UTS namespace with:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
호스트네임 변경은 해당 네임스페이스에 로컬로만 적용되며 호스트의 전역 호스트네임을 변경하지 않습니다. 이는 격리 속성을 간단하지만 효과적으로 보여주는 예입니다.

## 런타임 사용

일반 컨테이너는 격리된 UTS 네임스페이스를 갖습니다. Docker와 Podman은 `--uts=host`를 통해 호스트 UTS 네임스페이스에 합류할 수 있으며, 유사한 호스트 공유 패턴이 다른 런타임 및 오케스트레이션 시스템에서도 나타날 수 있습니다. 그러나 대부분의 경우, 개인 UTS 격리는 일반적인 컨테이너 설정의 일부이며 운영자의 특별한 주의를 거의 필요로 하지 않습니다.

## 보안 영향

UTS 네임스페이스는 보통 공유했을 때 가장 위험한 네임스페이스는 아니지만, 여전히 컨테이너 경계의 무결성에 기여합니다. 호스트 UTS 네임스페이스가 노출되고 프로세스가 필요한 권한을 가지고 있다면 호스트의 호스트네임 관련 정보를 변경할 수 있습니다. 이는 모니터링, 로깅, 운영상의 가정 또는 호스트 식별 데이터를 기반으로 신뢰 결정을 내리는 스크립트에 영향을 줄 수 있습니다.

## 악용

호스트 UTS 네임스페이스가 공유된 경우, 실제적인 질문은 프로세스가 단순히 읽는 것만 가능한지 아니면 호스트 식별 설정을 수정할 수 있는지 여부입니다:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
container에 필요한 권한이 있는 경우 hostname을 변경할 수 있는지 테스트하세요:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
이는 주로 무결성 및 운영 영향(integrity and operational-impact) 문제이지 완전한 full escape라기보다는, 컨테이너가 호스트 전역(host-global) 속성을 직접 조작할 수 있음을 보여준다.

영향:

- 호스트 신원 변조
- hostname을 신뢰하는 로그, 모니터링 또는 자동화의 혼란
- 보통 다른 약점들과 결합되지 않는 한 단독으로는 full escape가 아니다

On Docker-style environments, a useful host-side detection pattern is:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host`로 표시된 컨테이너는 호스트 UTS 네임스페이스를 공유하며, `sethostname()` 또는 `setdomainname()`을 호출할 수 있는 capabilities를 가지고 있다면 더 면밀히 검토해야 합니다.

## 검사

이 명령어들로 워크로드가 자체 hostname 뷰를 가지고 있는지 또는 호스트 UTS 네임스페이스를 공유하는지 확인할 수 있습니다.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
여기서 흥미로운 점:

- Matching namespace identifiers with a host process may indicate host UTS sharing.
- If changing the hostname affects more than the container itself, the workload has more influence over host identity than it should.
- This is usually a lower-priority finding than PID, mount, or user namespace issues, but it still confirms how isolated the process really is.

대부분의 환경에서 UTS namespace는 보조적인 isolation layer로 생각하는 것이 적절하다. breakout에서 가장 먼저 추적하는 대상은 드물지만, 여전히 container 관점의 전체 일관성과 안전성의 일부이다.
