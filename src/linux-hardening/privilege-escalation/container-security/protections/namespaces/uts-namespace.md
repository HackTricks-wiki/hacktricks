# UTS 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

UTS 네임스페이스는 프로세스가 보는 **호스트명**과 **NIS 도메인 이름**을 격리합니다. 언뜻 보기에는 mount, PID, 또는 user 네임스페이스와 비교해 사소해 보일 수 있지만, 이는 컨테이너가 자체 호스트인 것처럼 보이게 만드는 요소의 일부입니다. 네임스페이스 내부에서는 워크로드가 시스템 전체에 적용되는 전역 호스트명이 아니라 해당 네임스페이스에 국한된 호스트명을 볼 수 있고 때때로 변경할 수 있습니다.

단독으로는 보통 탈출(breakout) 스토리의 핵심이 되지 않습니다. 하지만 호스트 UTS 네임스페이스가 공유되면 충분한 권한을 가진 프로세스가 호스트 식별 관련 설정에 영향을 줄 수 있으며, 이는 운영상 그리고 때때로 보안상 중요할 수 있습니다.

## 실습

다음 명령으로 UTS 네임스페이스를 생성할 수 있습니다:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
호스트네임 변경은 해당 네임스페이스 내에서만 적용되며 호스트의 전역 호스트네임을 변경하지 않습니다. 이는 격리 속성을 간단하면서도 효과적으로 보여주는 예입니다.

## 런타임 사용

일반적인 컨테이너는 격리된 UTS 네임스페이스를 가집니다. Docker와 Podman은 `--uts=host`를 통해 호스트 UTS 네임스페이스에 합류할 수 있으며, 유사한 호스트 공유 패턴이 다른 런타임이나 오케스트레이션 시스템에서도 나타날 수 있습니다. 대부분의 경우에는 개인 UTS 격리가 일반적인 컨테이너 설정의 일부일 뿐이며 운영자가 따로 신경 쓸 필요는 거의 없습니다.

## 보안 영향

UTS 네임스페이스는 일반적으로 공유 시 가장 위험한 네임스페이스는 아니지만, 컨테이너 경계의 무결성에 기여합니다. 호스트 UTS 네임스페이스가 노출되고 프로세스가 필요한 권한을 가지고 있다면 호스트의 hostname 관련 정보를 변경할 수 있습니다. 이는 모니터링, 로깅, 운영상의 가정 또는 호스트 식별 데이터에 기반해 신뢰 결정을 내리는 스크립트에 영향을 줄 수 있습니다.

## 악용

호스트 UTS 네임스페이스가 공유된 경우, 실무적으로 중요한 질문은 프로세스가 단순히 이를 읽는 것만 가능한지 아니면 호스트 식별 설정을 수정할 수 있는지 여부입니다:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
컨테이너에 필요한 권한이 있다면 호스트네임을 변경할 수 있는지 테스트해보세요:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
이 문제는 주로 무결성과 운영 영향(operational-impact)에 관한 것으로, 완전한 escape라기보다는 그렇지만 컨테이너가 호스트 전역 속성(host-global property)에 직접 영향을 줄 수 있음을 보여준다.

영향:

- 호스트 식별 위조
- hostname을 신뢰하는 로그, 모니터링 또는 자동화의 혼란
- 보통 단독으로는 완전한 escape가 아니며 다른 약점과 결합될 때 문제가 됨

Docker 스타일 환경에서는 유용한 호스트 측 탐지 패턴은 다음과 같다:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host`를 표시하는 컨테이너는 호스트 UTS 네임스페이스를 공유하므로, `sethostname()` 또는 `setdomainname()`을 호출할 수 있는 capabilities를 가지고 있다면 더 면밀히 검토해야 합니다.

## 확인

다음 명령들로 워크로드가 자체 hostname 보기를 갖는지, 아니면 호스트 UTS 네임스페이스를 공유하는지 확인할 수 있습니다.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
- 네임스페이스 식별자(namespace identifiers)가 호스트 프로세스와 일치하면 호스트 UTS 공유를 나타낼 수 있다.
- hostname을 변경했을 때 container 자체 이상에 영향을 미친다면, 해당 workload는 호스트 identity에 과도한 영향을 주고 있는 것이다.
- 이는 보통 PID, mount, 또는 user namespace 문제보다 우선순위가 낮은 발견사항이지만, 프로세스가 실제로 얼마나 격리되어 있는지를 확인해 준다.

대부분 환경에서 UTS namespace는 보조적인 격리 레이어로 생각하는 것이 가장 좋다. 보통 breakout을 추적할 때 가장 먼저 확인하는 항목은 아니지만, container의 전체적인 일관성과 안전성의 일부라는 점은 여전히 중요하다.
{{#include ../../../../../banners/hacktricks-training.md}}
