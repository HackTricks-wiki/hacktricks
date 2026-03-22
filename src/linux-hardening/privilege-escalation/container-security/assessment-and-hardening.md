# 평가 및 강화

{{#include ../../../banners/hacktricks-training.md}}

## 개요

좋은 컨테이너 평가는 두 가지 병행되는 질문에 답해야 합니다. 첫째, 현재 workload에서 공격자가 무엇을 할 수 있는가? 둘째, 어떤 운영자 선택들이 그것을 가능하게 했는가? 열거 도구들은 첫 번째 질문에 도움이 되고, 하드닝 지침은 두 번째 질문을 돕습니다. 둘을 한 페이지에 모아두면 단순한 escape tricks 목록보다 현장 참고 자료로 더 유용합니다.

## 열거 도구

여러 도구가 컨테이너 환경을 빠르게 특성화하는 데 유용합니다:

- `linpeas`는 많은 컨테이너 지표, 마운트된 소켓, capability 세트, 위험한 파일시스템과 탈출 힌트를 식별할 수 있습니다.
- `CDK`는 컨테이너 환경에 특화되어 열거와 몇 가지 자동화된 탈출 검사들을 포함합니다.
- `amicontained`는 경량이며 컨테이너 제한, capabilities, namespace 노출 및 가능한 탈출 클래스 식별에 유용합니다.
- `deepce`는 탈출 지향 검사를 포함한 또 다른 컨테이너 중심 열거 도구입니다.
- `grype`는 평가에 이미지-패키지 취약점 검토가 포함될 때 유용합니다(단순 런타임 탈출 분석만이 아닐 경우).

이 도구들의 가치는 속도와 범위에 있으며 확실성이 아닙니다. 대략적인 태세를 빠르게 드러내는 데 도움이 되지만, 흥미로운 발견들은 여전히 실제 runtime, namespace, capability 및 mount 모델에 대해 수동으로 해석해야 합니다.

## 하드닝 우선순위

가장 중요한 하드닝 원칙들은 개념적으로 단순하지만 구현은 플랫폼마다 다릅니다. 특권이 부여된 컨테이너는 피하세요. 마운트된 runtime 소켓을 피하세요. 아주 특별한 이유가 없는 한 컨테이너에 호스트 경로를 쓰기 가능하게 주지 마세요. 가능하면 user namespaces 또는 rootless 실행을 사용하세요. 모든 capabilities를 제거하고 workload가 실제로 필요로 하는 것만 다시 추가하세요. 애플리케이션 호환성 문제를 해결하기 위해 이들을 비활성화하기보다는 seccomp, AppArmor, SELinux를 활성화 상태로 유지하세요. 탈취된 컨테이너가 호스트에 대해 쉽게 서비스 거부를 일으킬 수 없도록 리소스를 제한하세요.

이미지 및 빌드 위생은 runtime 태세만큼 중요합니다. 최소 이미지 사용, 자주 재빌드, 이미지 스캔, 가능한 경우 provenance(출처)를 요구하고 레이어에 비밀을 넣지 마세요. non-root로 실행되며 작은 이미지, 좁은 syscall 및 capability 표면을 가진 컨테이너는 디버깅 도구가 미리 설치되어 있고 호스트 동급 root로 실행되는 대형 편의 이미지보다 방어가 훨씬 쉽습니다.

## 자원 고갈 예시

자원 제어는 화려하지는 않지만 침탈의 영향 범위를 제한하기 때문에 컨테이너 보안의 일부입니다. 메모리, CPU, PID 제한이 없으면 단순한 쉘도 호스트나 인접한 workloads를 저하시킬 수 있습니다.

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
이 예시들은 모든 위험한 컨테이너 결과가 깔끔한 "escape"인 것은 아님을 보여주기 때문에 유용하다. 약한 cgroup 제한은 여전히 code execution을 실제 운영 영향으로 전환시킬 수 있다.

## 하드닝 도구

Docker-centric 환경에서는, `docker-bench-security`가 호스트 측 감사 기준선으로 여전히 유용하다. 이는 널리 인정된 벤치마크 지침에 따라 일반적인 구성 문제를 검사하기 때문이다:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
이 도구는 threat modeling을 대체할 수는 없지만, 시간이 지나면서 누적되는 부주의한 daemon, mount, network 및 runtime defaults를 찾는 데 여전히 유용합니다.

## 점검

평가 중에 빠른 1차 확인용 명령으로 다음을 사용하세요:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- 광범위한 권한을 가진 root 프로세스와 `Seccomp: 0`은 즉각적인 주의가 필요합니다.
- 의심스러운 마운트와 런타임 소켓은 종종 어떤 kernel exploit보다도 더 빠르게 영향 경로를 제공합니다.
- 약한 런타임 보안 태세와 느슨한 리소스 제한의 조합은 보통 단일 고립된 실수보다는 전반적으로 허용적인 컨테이너 환경을 나타냅니다.
{{#include ../../../banners/hacktricks-training.md}}
