# UTS 네임스페이스

{{#include ../../../../../banners/hacktricks-training.md}}

## 개요

UTS 네임스페이스는 프로세스에 표시되는 **호스트 이름**과 **NIS 도메인 이름**을 격리합니다. 처음에는 mount, PID 또는 user namespaces와 비교해 사소해 보일 수 있지만, 컨테이너가 자체 호스트처럼 보이게 만드는 요소 중 하나입니다. 네임스페이스 내부에서 workload는 머신 전체에 전역적으로 적용되는 호스트 이름이 아니라 해당 네임스페이스에 로컬인 호스트 이름을 확인하고, 경우에 따라 변경할 수 있습니다.

이 기능만으로는 일반적으로 breakout의 핵심이 되지 않습니다. 하지만 host UTS namespace를 공유하면 충분한 권한을 가진 프로세스가 호스트 identity 관련 설정에 영향을 줄 수 있으며, 이는 운영 측면에서 중요할 수 있고 때로는 보안 측면에서도 문제가 될 수 있습니다.

## 실습

다음 명령으로 UTS namespace를 생성할 수 있습니다:
```bash
sudo unshare --uts --fork bash
hostname
hostname lab-container
hostname
```
호스트 이름 변경은 해당 namespace에만 로컬로 적용되며 호스트의 전역 hostname은 변경하지 않습니다. 이는 격리 속도를 간단하면서도 효과적으로 보여주는 예입니다.

## 런타임 사용

일반적인 containers는 격리된 UTS namespace를 사용합니다. Docker와 Podman은 `--uts=host`를 통해 호스트 UTS namespace에 참여할 수 있으며, 다른 runtimes와 orchestration systems에서도 유사한 호스트 공유 패턴이 나타날 수 있습니다. 하지만 대부분의 경우 private UTS isolation은 일반적인 container 설정의 일부이며 operator의 특별한 개입이 거의 필요하지 않습니다.

## 보안 영향

UTS namespace는 일반적으로 공유하기에 가장 위험한 namespace는 아니지만, 여전히 container boundary의 무결성에 기여합니다. 호스트 UTS namespace가 노출되고 process에 필요한 privileges가 있다면, 호스트의 hostname 관련 정보를 변경할 수 있습니다. 이는 monitoring, logging, 운영상의 가정 또는 호스트 identity data를 기반으로 trust 결정을 내리는 scripts에 영향을 줄 수 있습니다.

## 악용

호스트 UTS namespace가 공유된 경우, 실제로 중요한 질문은 process가 단순히 읽는 것을 넘어 호스트 identity 설정을 수정할 수 있는지 여부입니다:
```bash
readlink /proc/self/ns/uts
hostname
cat /proc/sys/kernel/hostname
```
컨테이너에도 필요한 권한이 있다면 hostname을 변경할 수 있는지 테스트합니다:
```bash
hostname hacked-host 2>/dev/null && echo "hostname change worked"
hostname
```
이는 완전한 escape라기보다는 무결성 및 운영 영향 문제에 가깝지만, 컨테이너가 호스트 전역 속성에 직접 영향을 줄 수 있음을 보여줍니다.

영향:

- 호스트 identity 변조
- hostname을 신뢰하는 로그, 모니터링 또는 자동화의 혼란
- 일반적으로 단독으로는 완전한 escape가 아니며, 다른 weakness와 결합되는 경우를 제외함

Docker-style 환경에서는 호스트 측에서 다음과 같은 detection pattern을 유용하게 사용할 수 있습니다:
```bash
docker ps -aq | xargs -r docker inspect --format '{{.Id}} UTSMode={{.HostConfig.UTSMode}}'
```
`UTSMode=host`가 표시되는 컨테이너는 호스트 UTS namespace를 공유하므로, `sethostname()` 또는 `setdomainname()`을 호출할 수 있는 capabilities도 보유하고 있다면 더 주의 깊게 검토해야 합니다.

## Checks

다음 명령어로 워크로드가 자체 hostname view를 사용하는지, 아니면 호스트 UTS namespace를 공유하는지 확인할 수 있습니다.
```bash
readlink /proc/self/ns/uts   # UTS namespace identifier
hostname                     # Hostname as seen by the current process
cat /proc/sys/kernel/hostname   # Kernel hostname value in this namespace
```
여기서 흥미로운 점:

- namespace 식별자가 host 프로세스와 일치하면 host UTS sharing을 나타낼 수 있습니다.
- hostname을 변경했을 때 container 자체보다 더 많은 대상에 영향을 미친다면, 해당 workload가 host identity에 필요한 수준보다 더 큰 영향력을 갖고 있는 것입니다.
- 이는 일반적으로 PID, mount 또는 user namespace 문제보다 우선순위가 낮은 finding이지만, 프로세스가 실제로 얼마나 격리되어 있는지 확인해 줍니다.

대부분의 환경에서 UTS namespace는 보조적인 isolation layer로 보는 것이 가장 적절합니다. breakout에서 가장 먼저 추적하는 대상인 경우는 드물지만, container view의 전반적인 일관성과 안전성을 구성하는 요소이기도 합니다.
{{#include ../../../../../banners/hacktricks-training.md}}
