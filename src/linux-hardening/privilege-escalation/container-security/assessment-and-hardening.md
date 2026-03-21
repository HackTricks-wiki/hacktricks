# 평가 및 강화

{{#include ../../../banners/hacktricks-training.md}}

## 개요

좋은 container 평가는 두 가지 병렬 질문에 답해야 합니다. 첫째, 현재 workload에서 공격자가 무엇을 할 수 있는가? 둘째, 어떤 운영자 선택이 그것을 가능하게 했는가? Enumeration 도구는 첫 번째 질문을 돕고, hardening 지침은 두 번째 질문을 돕습니다. 둘을 한 페이지에 함께 두면 단순한 escape tricks 목록보다 현장 참고서로서 더 유용합니다.

## Enumeration Tools

다음 도구들은 container 환경을 빠르게 특성화하는 데 유용합니다:

- `linpeas`는 많은 container 지표, mounted sockets, capability sets, 위험한 filesystems 및 breakout 힌트를 식별할 수 있습니다.
- `CDK`는 특히 container 환경에 중점을 두며 열거와 일부 자동화된 escape 검사들을 포함합니다.
- `amicontained`는 경량으로 container 제한, capabilities, namespace 노출 및 가능한 breakout 클래스 식별에 유용합니다.
- `deepce`는 breakout 지향 검사들을 제공하는 또 다른 container 중심 열거 도구입니다.
- `grype`는 평가에 이미지-패키지 취약성 검토가 포함될 때(단순히 runtime escape 분석만이 아닐 경우) 유용합니다.

이 도구들의 가치는 속도와 범위에 있으며, 확실성을 보장하지는 않습니다. 이들은 대강의 태세를 빠르게 드러내는 데 도움을 주지만, 흥미로운 발견은 실제 runtime, namespace, capability 및 mount 모델에 대해 수동으로 해석할 필요가 있습니다.

## 강화 우선순위

가장 중요한 hardening 원칙들은 개념적으로 단순하지만 플랫폼마다 구현은 다릅니다. privileged containers를 피하세요. mounted runtime sockets를 피하세요. 아주 구체적인 이유가 없는 한 컨테이너에 쓰기 가능한 host 경로를 주지 마세요. 가능한 경우 user namespaces 또는 rootless execution을 사용하세요. 모든 capabilities를 제거하고 workload가 실제로 필요로 하는 것만 다시 추가하세요. 호환성 문제 해결을 위해 seccomp, AppArmor, SELinux를 비활성화하기보다는 활성 상태로 유지하세요. 타당한 리소스 제한을 설정하여 탈취된 컨테이너가 host에 서비스 거부를 쉽게 일으키지 못하도록 하세요.

이미지 및 빌드 위생은 runtime 태세만큼 중요합니다. 최소한의 image를 사용하고 자주 rebuild하며 스캔하고, 실용적일 경우 출처를 요구하고, 레이어에 비밀을 남기지 마세요. non-root로 실행되는 작은 image와 좁은 syscall 및 capability 표면을 가진 컨테이너는 debugging 도구가 사전 설치된 host-동등한 root로 실행되는 큰 편의성 image보다 방어하기 훨씬 쉽습니다.

## 자원 고갈 예시

리소스 제어는 화려하진 않지만 compromise의 영향 반경을 제한하기 때문에 container 보안의 일부입니다. 메모리, CPU, 또는 PID 제한이 없으면 간단한 shell만으로도 host나 인접한 workloads를 저하시킬 수 있습니다.

Example host-impacting tests:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
이 예제들은 모든 위험한 container 결과가 깔끔한 "escape"가 되는 것은 아니라는 것을 보여주기 때문에 유용합니다. 약한 cgroup limits는 여전히 code execution을 실제 운영상 영향으로 전환시킬 수 있습니다.

## Hardening Tooling

Docker-centric 환경에서는 `docker-bench-security`가 여전히 유용한 호스트 측 감사 기준선으로 남아있습니다. 이는 널리 인정된 벤치마크 가이드라인에 따라 일반적인 구성 문제를 검사하기 때문입니다:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
이 도구는 threat modeling을 대체하지는 않지만, 시간이 지나면서 누적되는 부주의한 daemon, mount, network, 및 runtime defaults를 찾아내는 데 여전히 유용합니다.

## 검사

평가 중에 1차로 빠르게 실행할 명령은 다음과 같습니다:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- 광범위한 capabilities를 가진 root process와 `Seccomp: 0`은 즉각적인 주의가 필요하다.
- Suspicious mounts와 runtime sockets는 종종 어떤 kernel exploit보다도 더 빠르게 영향을 미칠 수 있는 경로를 제공한다.
- weak runtime posture와 weak resource limits의 조합은 대개 단일한 고립된 실수라기보다는 전반적으로 permissive container environment를 의미한다.
